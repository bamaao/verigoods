//! ownership 上下文：所有权与保管的分离模型。
//!
//! - [`states`]：所有权状态（owner + 转移计数）与保管状态（custodian）；
//! - [`transfer`]：转移审计记录与保管变更事件；
//! - [`ports`]：持久化端口（由基础设施层实现，领域层只定义契约）。
//!
//! ## 核心不变量：所有权 / 保管完全分离
//!
//! 对应链上 [`OwnershipRegistry`](https://github.com/VeriGoods/commodity-network-smart-contracts)
//! 与物流托管两条独立记录线：
//! - 转移所有权只改 `owner` / `acquired_at` / 计数器，**不触碰** custodian；
//! - 保管变更独立成事件（[`CustodyUpdate`]），只改 `custodian` / `since`，
//!   **不触碰** owner 与计数器。
//!
//! 两个值对象除 `subject` 外字段零交集，仓储端口亦分列
//! `init_owner`/`get`/`save` 与 `update_custody`，审计线独立为
//! `record_transfer`/`history`（追加式、按记录 ID 幂等）。

pub mod states;
pub mod transfer;

pub use states::{CustodyState, OwnershipState};
pub use transfer::{CustodyReason, CustodyUpdate, TransferRecord};

/// ownership 上下文的端口集合。
pub mod ports {
    use async_trait::async_trait;

    use crate::shared::{DomainError, SubjectRef};

    use super::{CustodyState, OwnershipState, TransferRecord};

    /// 所有权/保管状态的持久化端口。
    ///
    /// 实现方为具体存储适配器（如 PostgreSQL，Task 16）；领域层与测试用内存实现。
    #[async_trait]
    pub trait OwnershipRepository {
        /// 事务/会话上下文类型，由实现方定义。
        ///
        /// 必须为 `Send`：axum handler 要求 future 为 `Send`，
        /// 跨 `.await` 持有 ctx 时该关联类型约束是前提
        /// （与 identity / credential / lifecycle / commodity 同一约定）。
        type Context: Send;

        /// 初始化某主体的所有权档案（对应合约 `OwnershipRegistry.initializeOwner`）。
        ///
        /// 合约的 `require(ownerDid == bytes32(0), "owner exists")` revert 在此
        /// 落地为唯一约束：同主体已存在所有权档案时必须返回
        /// [`DomainError::AlreadyExists`]，由存储层保证"一个主体至多一条
        /// 所有权档案"的领域不变式。
        async fn init_owner(
            &self,
            ctx: &mut Self::Context,
            state: &OwnershipState,
        ) -> Result<(), DomainError>;

        /// 按主体查询当前所有权；不存在时返回 `Ok(None)`。
        async fn get(
            &self,
            ctx: &mut Self::Context,
            subject: &SubjectRef,
        ) -> Result<Option<OwnershipState>, DomainError>;

        /// 整体替换保存所有权状态：转移写路径 `get` → [`OwnershipState::transfer`]
        /// → `save` 的落库端。
        ///
        /// upsert 语义（与 commodity 的 `save_*` 同款）：正常流程先经
        /// [`Self::init_owner`] 建档，本方法用于后续变更的整体替换。
        async fn save(
            &self,
            ctx: &mut Self::Context,
            state: &OwnershipState,
        ) -> Result<(), DomainError>;

        /// 按主体查询当前保管状态；不存在时返回 `Ok(None)`。
        ///
        /// 读侧自然延伸：`update_custody` 的写入对称面，供应用层读取
        /// 现任 custodian（保管链条交接的前手校验、CustodyChanged 事件的
        /// `from` 字段等），消除 handler 直查 SQL 的层级泄漏。
        async fn get_custody(
            &self,
            ctx: &mut Self::Context,
            subject: &SubjectRef,
        ) -> Result<Option<CustodyState>, DomainError>;

        /// 记录一次保管状态（upsert：无则建档，有则覆盖 custodian/since）。
        ///
        /// 保管与所有权的存储完全独立，本方法不读取也不校验所有权档案。
        async fn update_custody(
            &self,
            ctx: &mut Self::Context,
            custody: &CustodyState,
        ) -> Result<(), DomainError>;

        /// 追加一条所有权转移记录到审计日志。
        ///
        /// 幂等语义：按 `record.id` 去重，重复提交同一条记录不产生新条目
        /// （pg 实现可用 `record.id` 唯一键落地同一语义）。
        async fn record_transfer(
            &self,
            ctx: &mut Self::Context,
            record: &TransferRecord,
        ) -> Result<(), DomainError>;

        /// 返回某主体**按追加序**排列的全部所有权转移记录（审计回放）。
        async fn history(
            &self,
            ctx: &mut Self::Context,
            subject: &SubjectRef,
        ) -> Result<Vec<TransferRecord>, DomainError>;
    }
}

#[cfg(test)]
mod tests {
    use super::ports::OwnershipRepository;
    use super::*;
    use crate::shared::{BatchId, Did, DomainError, SubjectRef};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::collections::HashMap;
    use std::future::Future;

    // ---- 内存仓储：锁定端口形状，并作为存储适配器的参考实现 ----

    #[derive(Default)]
    struct MemStore {
        owners: HashMap<SubjectRef, OwnershipState>,
        custody: HashMap<SubjectRef, CustodyState>,
        transfers: Vec<TransferRecord>,
    }

    struct MemRepo;

    #[async_trait]
    impl OwnershipRepository for MemRepo {
        type Context = MemStore;

        async fn init_owner(
            &self,
            ctx: &mut Self::Context,
            state: &OwnershipState,
        ) -> Result<(), DomainError> {
            // 唯一约束：同主体重复初始化 → AlreadyExists（合约 "owner exists"）
            if ctx.owners.contains_key(&state.subject) {
                return Err(DomainError::AlreadyExists);
            }
            ctx.owners.insert(state.subject.clone(), state.clone());
            Ok(())
        }

        async fn get(
            &self,
            ctx: &mut Self::Context,
            subject: &SubjectRef,
        ) -> Result<Option<OwnershipState>, DomainError> {
            Ok(ctx.owners.get(subject).cloned())
        }

        async fn save(
            &self,
            ctx: &mut Self::Context,
            state: &OwnershipState,
        ) -> Result<(), DomainError> {
            // 整体替换（upsert）：正常流程先经 init_owner 建档
            ctx.owners.insert(state.subject.clone(), state.clone());
            Ok(())
        }

        async fn get_custody(
            &self,
            ctx: &mut Self::Context,
            subject: &SubjectRef,
        ) -> Result<Option<CustodyState>, DomainError> {
            Ok(ctx.custody.get(subject).cloned())
        }

        async fn update_custody(
            &self,
            ctx: &mut Self::Context,
            custody: &CustodyState,
        ) -> Result<(), DomainError> {
            // upsert：保管与所有权存储完全独立
            ctx.custody.insert(custody.subject.clone(), custody.clone());
            Ok(())
        }

        async fn record_transfer(
            &self,
            ctx: &mut Self::Context,
            record: &TransferRecord,
        ) -> Result<(), DomainError> {
            // 幂等：按记录 ID 去重（pg 侧唯一键落地同一语义）
            if ctx.transfers.iter().any(|r| r.id == record.id) {
                return Ok(());
            }
            ctx.transfers.push(record.clone());
            Ok(())
        }

        async fn history(
            &self,
            ctx: &mut Self::Context,
            subject: &SubjectRef,
        ) -> Result<Vec<TransferRecord>, DomainError> {
            Ok(ctx
                .transfers
                .iter()
                .filter(|r| &r.subject == subject)
                .cloned()
                .collect())
        }
    }

    /// 极简 block_on（与 identity / lifecycle / commodity 同款）：内存 fake 的
    /// future 永远就绪，noop waker 即足够；领域层禁止引入 tokio 等运行时依赖，
    /// 测试自带最小驱动器。
    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        loop {
            if let std::task::Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
            // 内存实现不会真正 Pending；若意外 Pending 则自旋重试。
        }
    }

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 0, 0, 0).unwrap()
    }

    fn later_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 6, 0, 0).unwrap()
    }

    fn batch_subject(id: &str) -> SubjectRef {
        SubjectRef::Batch(BatchId::new(id))
    }

    fn alice() -> Did {
        Did::parse("did:vg:user:alice").unwrap()
    }

    fn bob() -> Did {
        Did::parse("did:vg:user:bob").unwrap()
    }

    fn carol() -> Did {
        Did::parse("did:vg:user:carol").unwrap()
    }

    #[test]
    fn ownership_repository_roundtrips_ownership_custody_and_history() {
        let repo = MemRepo;
        let mut ctx = MemStore::default();
        let subject = batch_subject("b-repo-1");

        // 空库：get 为 None、history 为空
        assert!(block_on(repo.get(&mut ctx, &subject))
            .expect("查询不应报错")
            .is_none());
        assert!(block_on(repo.history(&mut ctx, &subject))
            .expect("查询不应报错")
            .is_empty());

        // 初始化所有权并回读一致
        let state = OwnershipState::initialize(subject.clone(), alice(), fixed_time());
        block_on(repo.init_owner(&mut ctx, &state)).expect("初始化应成功");
        let found = block_on(repo.get(&mut ctx, &subject))
            .expect("查询不应报错")
            .expect("刚建档的所有权应能查到");
        assert_eq!(found, state);

        // 初始托管登记并经端口回读（get_custody 读侧对称面）
        assert!(
            block_on(repo.get_custody(&mut ctx, &subject))
                .expect("查询不应报错")
                .is_none(),
            "未建档前 get_custody 应为 None"
        );
        let courier = Did::parse("did:vg:user:courier-a").unwrap();
        block_on(repo.update_custody(
            &mut ctx,
            &CustodyState::new(subject.clone(), courier.clone(), fixed_time()),
        ))
        .expect("托管登记应成功");
        let stored_custody = block_on(repo.get_custody(&mut ctx, &subject))
            .expect("查询不应报错")
            .expect("刚登记的保管档案应能查到");
        assert_eq!(stored_custody.custodian, courier);
        assert_eq!(stored_custody.since, fixed_time());

        // 两笔转移：普通 → C2C；经端口追加审计记录后按追加序完整取回
        let mut state = found;
        let r1 = state
            .transfer(&bob(), false, later_time())
            .expect("转移应成功");
        let r2 = state
            .transfer(&carol(), true, later_time())
            .expect("转移应成功");
        block_on(repo.record_transfer(&mut ctx, &r1)).expect("追加记录应成功");
        block_on(repo.record_transfer(&mut ctx, &r2)).expect("追加记录应成功");

        let history = block_on(repo.history(&mut ctx, &subject)).expect("查询不应报错");
        assert_eq!(history.len(), 2, "只应包含 b-repo-1 的两笔转移");
        assert_eq!(history[0], r1, "第一笔记录字段应完整一致");
        assert_eq!(history[1], r2, "第二笔记录字段应完整一致");
        assert!(!history[0].c2c && history[1].c2c);
        assert_eq!((history[1].transfer_count, history[1].c2c_count), (2, 1));

        // 无关主体的记录互不可见
        let other = batch_subject("b-repo-2");
        assert!(block_on(repo.history(&mut ctx, &other))
            .expect("查询不应报错")
            .is_empty());
    }

    #[test]
    fn init_owner_twice_is_already_exists_like_contract_owner_exists() {
        let repo = MemRepo;
        let mut ctx = MemStore::default();
        let subject = batch_subject("b-dup-1");

        let first = OwnershipState::initialize(subject.clone(), alice(), fixed_time());
        block_on(repo.init_owner(&mut ctx, &first)).expect("首次初始化应成功");

        let second = OwnershipState::initialize(subject.clone(), bob(), later_time());
        let err = block_on(repo.init_owner(&mut ctx, &second)).expect_err("重复初始化必须被拒绝");
        assert!(
            matches!(err, DomainError::AlreadyExists),
            "对应合约 revert \"owner exists\"，实际错误：{err:?}"
        );
        // 原档案不被覆盖
        let kept = block_on(repo.get(&mut ctx, &subject))
            .expect("查询不应报错")
            .expect("原档案应保留");
        assert_eq!(kept.owner, alice());
    }

    #[test]
    fn save_completes_get_transfer_save_write_path() {
        let repo = MemRepo;
        let mut ctx = MemStore::default();
        let subject = batch_subject("b-save-1");
        block_on(repo.init_owner(
            &mut ctx,
            &OwnershipState::initialize(subject.clone(), alice(), fixed_time()),
        ))
        .expect("初始化应成功");

        // get → transfer → save：应用层经由端口即可完成整个转移落库
        let mut state = block_on(repo.get(&mut ctx, &subject))
            .expect("查询不应报错")
            .expect("所有权应存在");
        let record = state
            .transfer(&bob(), true, later_time())
            .expect("转移应成功");
        block_on(repo.save(&mut ctx, &state)).expect("save 应成功");
        block_on(repo.record_transfer(&mut ctx, &record)).expect("record_transfer 应成功");

        // 所有权状态整体替换生效：owner/计数器/acquired_at 全部落库
        let stored = block_on(repo.get(&mut ctx, &subject))
            .expect("查询不应报错")
            .expect("所有权应存在");
        assert_eq!(stored.owner, bob());
        assert_eq!((stored.transfer_count, stored.c2c_count), (1, 1));
        assert_eq!(stored.acquired_at, later_time());

        // 审计日志含且仅含该笔记录
        let history = block_on(repo.history(&mut ctx, &subject)).expect("查询不应报错");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0], record);
    }

    #[test]
    fn record_transfer_deduplicates_by_record_id() {
        let repo = MemRepo;
        let mut ctx = MemStore::default();
        let subject = batch_subject("b-idem-1");
        block_on(repo.init_owner(
            &mut ctx,
            &OwnershipState::initialize(subject.clone(), alice(), fixed_time()),
        ))
        .expect("初始化应成功");

        let mut state = block_on(repo.get(&mut ctx, &subject))
            .expect("查询不应报错")
            .expect("所有权应存在");
        let r1 = state
            .transfer(&bob(), false, later_time())
            .expect("转移应成功");
        let r2 = state
            .transfer(&carol(), true, later_time())
            .expect("转移应成功");

        block_on(repo.record_transfer(&mut ctx, &r1)).expect("首次追加应成功");
        block_on(repo.record_transfer(&mut ctx, &r2)).expect("追加应成功");
        // 幂等：同一记录（同 id）重复提交不产生新条目
        block_on(repo.record_transfer(&mut ctx, &r1)).expect("重复提交应幂等成功");

        let history = block_on(repo.history(&mut ctx, &subject)).expect("查询不应报错");
        assert_eq!(history.len(), 2, "按 id 去重后应只有两笔记录");
        assert_eq!(history[0].id, r1.id);
        assert_eq!(history[1].id, r2.id);
    }

    #[test]
    fn ownership_transfer_and_custody_update_never_touch_each_other() {
        let repo = MemRepo;
        let mut ctx = MemStore::default();
        let subject = batch_subject("b-sep-1");
        let courier_a = Did::parse("did:vg:user:courier-a").unwrap();
        let courier_b = Did::parse("did:vg:user:courier-b").unwrap();

        // 初始：owner=alice、custodian=courier-a，两套档案各自就位
        block_on(repo.init_owner(
            &mut ctx,
            &OwnershipState::initialize(subject.clone(), alice(), fixed_time()),
        ))
        .expect("初始化所有权应成功");
        block_on(repo.update_custody(
            &mut ctx,
            &CustodyState::new(subject.clone(), courier_a.clone(), fixed_time()),
        ))
        .expect("初始托管登记应成功");

        // ---- 所有权转移：custodian / since 纹丝不动 ----
        let mut ownership = block_on(repo.get(&mut ctx, &subject))
            .expect("查询不应报错")
            .expect("所有权应存在");
        let record = ownership
            .transfer(&bob(), false, later_time())
            .expect("转移应成功");
        block_on(repo.save(&mut ctx, &ownership)).expect("保存转移结果应成功");
        block_on(repo.record_transfer(&mut ctx, &record)).expect("追加转移记录应成功");

        assert_eq!(
            ctx.custody.get(&subject).unwrap().custodian,
            courier_a,
            "转移所有权不得影响保管人"
        );
        assert_eq!(
            ctx.custody.get(&subject).unwrap().since,
            fixed_time(),
            "转移所有权不得刷新 since"
        );

        // ---- 保管更新：owner / 计数器纹丝不动 ----
        let mut custody = ctx.custody.get(&subject).unwrap().clone();
        let update = CustodyUpdate {
            subject: subject.clone(),
            from: Some(courier_a),
            to: courier_b.clone(),
            reason: CustodyReason::WarehouseIn,
        };
        custody
            .apply_update(&update, later_time())
            .expect("保管更新应成功");
        block_on(repo.update_custody(&mut ctx, &custody)).expect("保存保管应成功");

        let ownership_after = block_on(repo.get(&mut ctx, &subject))
            .expect("查询不应报错")
            .expect("所有权应存在");
        assert_eq!(ownership_after.owner, bob(), "保管更新不得影响所有者");
        assert_eq!(
            (ownership_after.transfer_count, ownership_after.c2c_count),
            (ownership.transfer_count, ownership.c2c_count),
            "保管更新不得影响计数器"
        );
        assert_eq!(
            ownership_after.acquired_at, ownership.acquired_at,
            "保管更新不得刷新取得时刻"
        );
        assert_eq!(ctx.custody.get(&subject).unwrap().custodian, courier_b);
        assert_eq!(ctx.custody.get(&subject).unwrap().since, later_time());

        // ---- 转移记录只反映所有权线，不含任何保管字段 ----
        let history = block_on(repo.history(&mut ctx, &subject)).expect("查询不应报错");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].from, alice());
        assert_eq!(history[0].to, bob());
    }

    /// 编译期哨兵（与 identity / lifecycle / commodity 同款）：`R::Context: Send`
    /// 必须由端口声明本身提供。
    fn requires_context_send<R: OwnershipRepository>(ctx: R::Context) {
        fn needs_send<T: Send>(_: T) {}
        needs_send(ctx);
    }

    #[test]
    fn port_context_must_be_send() {
        requires_context_send::<MemRepo>(MemStore::default());
    }
}
