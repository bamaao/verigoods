//! intent 上下文：Intent 聚合与持久化端口。
//!
//! [`Intent`] 是全系统**唯一的写入口径**（设计文档 §4）：任何写动作先落为
//! Intent，经「Schema 校验 → DID/Capability 授权 → VC 校验 → Policy Engine →
//! ZK Prover → Ledger 提交」管道逐级推进（§27 有向图），并按 §40 风险分级
//! （L1 自动 / L2 企业自动批准 / L3 额外授权 / L4 监管多签）决定审批形态。
//!
//! - [`intent`]：聚合根、动作枚举、风险分级与状态机；
//! - [`ports`]：Intent 持久化端口（由基础设施层实现）。

// plan 指定文件名 intent.rs，与目录同名触发 module_inception，按需豁免。
#[allow(clippy::module_inception)]
pub mod intent;

pub use intent::{
    assert_transition, can_transition, Intent, IntentAction, IntentStatus, RiskLevel,
    ALLOWED_TRANSITIONS,
};

/// intent 上下文的端口集合。
pub mod ports {
    use async_trait::async_trait;

    use crate::shared::{DomainError, IntentId};

    use super::{Intent, IntentStatus};

    /// Intent 的持久化端口（由 PostgreSQL 实现于后续任务；领域层与测试用内存实现）。
    #[async_trait]
    pub trait IntentRepository {
        /// 事务/会话上下文类型，由实现方定义。
        ///
        /// 必须为 `Send`：axum handler 要求 future 为 `Send`，
        /// 跨 `.await` 持有 ctx 时该关联类型约束是前提（与 identity / policy 同一约定）。
        type Context: Send;

        /// 插入新 Intent；主键冲突（同 id 已存在）返回 [`DomainError::AlreadyExists`]。
        ///
        /// 防重放的 `(actor, nonce)` 唯一性约束由 PostgreSQL 适配层承担
        /// （数据库层唯一索引），领域端口仅按 id 幂等。
        async fn insert(&self, ctx: &mut Self::Context, intent: &Intent)
            -> Result<(), DomainError>;

        /// 按 ID 查找；不存在时返回 `Ok(None)`。
        async fn get(
            &self,
            ctx: &mut Self::Context,
            id: &IntentId,
        ) -> Result<Option<Intent>, DomainError>;

        /// 更新指定 Intent 的状态（调用方负责先经 [`Intent::advance`] 裁决合法边）。
        ///
        /// 全量持久化 Intent（含 rejection/result_ref 等侧字段）。
        ///
        /// 供 reject(reason)/confirm(result_ref) 后的落库路径；upsert 语义：
        /// id 已存在时更新全部可变字段（status/risk/payload/nonce/expires_at/
        /// rejection/result_ref/updated_at），created_at 保留首建值。
        ///
        /// **陈旧快照契约**：调用方须保证 intent 是本事务内经
        /// [`IntentRepository::get`] 读出的实例、经领域方法推进后的结果；
        /// save 不做乐观并发防护（无 version 列），陈旧快照写入会**静默
        /// 覆盖**他人在此期间的推进。另 actor/nonce 不可变，篡改将触发
        /// UNIQUE 约束中止事务。
        async fn save(&self, ctx: &mut Self::Context, intent: &Intent) -> Result<(), DomainError>;

        /// 薄写入：仅持久化 status 字段（调用方负责先经 [`Intent::advance`]
        /// 裁决合法边）。
        ///
        /// `rejection` / `result_ref` 的持久化走 [`IntentRepository::save`]；
        /// 用本方法落终态时二者不随写。
        async fn update_status(
            &self,
            ctx: &mut Self::Context,
            id: &IntentId,
            to: &IntentStatus,
        ) -> Result<(), DomainError>;

        /// 列出全部非终态 Intent（供管道调度轮询推进）。
        ///
        /// 返回**所有**非终态（含已过期但未推进的项）；仓储不做时间假设，
        /// 调用方须自行用 [`Intent::is_replay_safe`] 过滤。
        async fn list_pending(&self, ctx: &mut Self::Context) -> Result<Vec<Intent>, DomainError>;
    }
}

#[cfg(test)]
mod tests {
    use super::ports::IntentRepository;
    use super::*;
    use crate::shared::{Did, DomainError, IntentId};
    use async_trait::async_trait;
    use chrono::TimeZone;
    use serde_json::json;
    use std::collections::HashMap;
    use std::future::Future;

    // ---- 内存仓储：锁定端口形状，并作为存储适配器的参考实现 ----

    #[derive(Default)]
    struct MemStore {
        intents: HashMap<String, Intent>,
    }

    struct MemRepo;

    #[async_trait]
    impl IntentRepository for MemRepo {
        type Context = MemStore;

        async fn insert(
            &self,
            ctx: &mut Self::Context,
            intent: &Intent,
        ) -> Result<(), DomainError> {
            if ctx.intents.contains_key(&intent.id.to_string()) {
                return Err(DomainError::AlreadyExists);
            }
            ctx.intents.insert(intent.id.to_string(), intent.clone());
            Ok(())
        }

        async fn get(
            &self,
            ctx: &mut Self::Context,
            id: &IntentId,
        ) -> Result<Option<Intent>, DomainError> {
            Ok(ctx.intents.get(&id.to_string()).cloned())
        }

        async fn save(&self, ctx: &mut Self::Context, intent: &Intent) -> Result<(), DomainError> {
            // HashMap 天然 upsert：id 已存在时整体覆盖（保留首建 created_at
            // 属持久化实现的列级职责，内存实现无该列，直接以入参为准）。
            ctx.intents.insert(intent.id.to_string(), intent.clone());
            Ok(())
        }

        async fn update_status(
            &self,
            ctx: &mut Self::Context,
            id: &IntentId,
            to: &IntentStatus,
        ) -> Result<(), DomainError> {
            let intent = ctx
                .intents
                .get_mut(&id.to_string())
                .ok_or(DomainError::NotFound)?;
            intent.status = *to;
            Ok(())
        }

        async fn list_pending(&self, ctx: &mut Self::Context) -> Result<Vec<Intent>, DomainError> {
            Ok(ctx
                .intents
                .values()
                .filter(|i| !i.status.is_terminal())
                .cloned()
                .collect())
        }
    }

    /// 极简 block_on（与 policy / identity 同款）：内存 fake 的 future 永远就绪，
    /// noop waker 即足够；领域层禁止引入 tokio 等运行时依赖。
    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        loop {
            if let std::task::Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }

    fn t() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn sample_intent(id: &str, nonce: u64) -> Intent {
        Intent::new(
            IntentId::new(id),
            IntentAction::CreateBatch,
            Did::parse("did:vg:user:alice").unwrap(),
            None,
            json!({"qty": 10}),
            nonce,
            t(),
            t() + chrono::Duration::hours(1),
        )
        .expect("样本构造应成功")
    }

    #[test]
    fn intent_repository_port_semantics() {
        let repo = MemRepo;
        let mut ctx = MemStore::default();

        // insert：成功 + 幂等冲突 → AlreadyExists
        let a = sample_intent("i-1", 1);
        block_on(repo.insert(&mut ctx, &a)).expect("首次插入应成功");
        let dup = sample_intent("i-1", 99);
        match block_on(repo.insert(&mut ctx, &dup)) {
            Err(DomainError::AlreadyExists) => {}
            other => panic!("重复插入应报 AlreadyExists，实际：{other:?}"),
        }
        // 冲突后原记录不被覆盖（nonce 保持原值）
        assert_eq!(
            block_on(repo.get(&mut ctx, &IntentId::new("i-1")))
                .expect("查询不应报错")
                .expect("i-1 应存在")
                .nonce,
            1
        );

        // get 未找到 → None
        assert!(block_on(repo.get(&mut ctx, &IntentId::new("nope")))
            .expect("查询不应报错")
            .is_none());

        // update_status：更新成功；不存在的 ID → NotFound
        block_on(repo.update_status(&mut ctx, &IntentId::new("i-1"), &IntentStatus::Validated))
            .expect("更新应成功");
        assert_eq!(
            block_on(repo.get(&mut ctx, &IntentId::new("i-1")))
                .expect("查询不应报错")
                .unwrap()
                .status,
            IntentStatus::Validated
        );
        match block_on(repo.update_status(
            &mut ctx,
            &IntentId::new("nope"),
            &IntentStatus::Approved,
        )) {
            Err(DomainError::NotFound) => {}
            other => panic!("更新不存在的 ID 应报 NotFound，实际：{other:?}"),
        }

        // save：upsert 全量覆盖——reject 场景的 rejection 随 save 落库
        let mut rejected = sample_intent("i-3", 3);
        rejected.reject("凭证缺失").expect("reject 应成功");
        block_on(repo.save(&mut ctx, &rejected)).expect("save 应成功");
        let saved = block_on(repo.get(&mut ctx, &IntentId::new("i-3")))
            .expect("查询不应报错")
            .expect("i-3 应存在");
        assert_eq!(saved, rejected, "save 后 get 应深相等（含 rejection）");
        assert_eq!(saved.rejection.as_deref(), Some("凭证缺失"));
        assert_eq!(saved.status, IntentStatus::Rejected);

        // save 对新 id 同样可用（首建路径）
        let fresh = sample_intent("i-4", 4);
        block_on(repo.save(&mut ctx, &fresh)).expect("save 新 id 应成功");
        assert_eq!(
            block_on(repo.get(&mut ctx, &IntentId::new("i-4")))
                .expect("查询不应报错")
                .expect("i-4 应存在"),
            fresh
        );

        // list_pending 只含非终态
        let mut confirmed = sample_intent("i-2", 2);
        confirmed
            .advance(IntentStatus::Validated)
            .and_then(|_| confirmed.advance(IntentStatus::Authorized))
            .and_then(|_| confirmed.advance(IntentStatus::PolicyChecked))
            .and_then(|_| confirmed.advance(IntentStatus::Approved))
            .and_then(|_| confirmed.advance(IntentStatus::Submitted))
            .and_then(|_| confirmed.advance(IntentStatus::Confirmed))
            .expect("测试路径推进不应失败");
        block_on(repo.insert(&mut ctx, &confirmed)).expect("插入应成功");
        let pending = block_on(repo.list_pending(&mut ctx)).expect("查询不应报错");
        assert_eq!(
            pending.len(),
            2,
            "i-1(Validated) 与 i-4(Created) 非终态；i-3 已 Rejected"
        );
        assert!(pending.iter().all(|i| !i.status.is_terminal()));
        assert!(pending.contains(
            &block_on(repo.get(&mut ctx, &IntentId::new("i-1")))
                .unwrap()
                .unwrap()
        ));
        assert!(pending.contains(
            &block_on(repo.get(&mut ctx, &IntentId::new("i-4")))
                .unwrap()
                .unwrap()
        ));
    }

    /// 编译期哨兵（与 policy / identity 同款）：`R::Context: Send`
    /// 必须由端口声明本身提供。
    fn requires_context_send<R: IntentRepository>(ctx: R::Context) {
        fn needs_send<T: Send>(_: T) {}
        needs_send(ctx);
    }

    #[test]
    fn port_context_must_be_send() {
        requires_context_send::<MemRepo>(MemStore::default());
    }
}
