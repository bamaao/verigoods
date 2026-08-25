//! lifecycle 上下文：商品生命周期状态机、事件与端口。
//!
//! - [`state`]：13 态状态机（转换矩阵 + 监管强制路径 + 迁移裁决，含上下架）；
//! - [`event`]：状态变更事件（不可变事实记录，构造即校验合法性）；
//! - [`ports`]：事件持久化与上链锚定端口（由基础设施层实现，领域层只定义契约）。

pub mod event;
pub mod state;

pub use event::LifecycleEvent;
pub use state::{assert_transition, can_transition, LifecycleState, ALLOWED_TRANSITIONS};

/// lifecycle 上下文的端口集合。
pub mod ports {
    use async_trait::async_trait;

    use crate::shared::{DomainError, SubjectRef};

    use super::event::LifecycleEvent;
    use super::state::LifecycleState;

    /// 生命周期事件的持久化端口（追加式事件日志）。
    ///
    /// 实现方为具体存储适配器（如 PostgreSQL，Task 16）；领域层与测试用内存实现。
    #[async_trait]
    pub trait LifecycleRepository {
        /// 事务/会话上下文类型，由实现方定义。
        ///
        /// 必须为 `Send`：axum handler 要求 future 为 `Send`，
        /// 跨 `.await` 持有 ctx 时该关联类型约束是前提
        /// （与 identity / credential 同一约定）。
        type Context: Send;

        /// 追加一条生命周期事件（按 `event.id` 幂等由实现方保证）。
        async fn append(
            &self,
            ctx: &mut Self::Context,
            event: &LifecycleEvent,
        ) -> Result<(), DomainError>;

        /// 返回某主体**按追加序**排列的全部生命周期事件。
        async fn history(
            &self,
            ctx: &mut Self::Context,
            subject: &SubjectRef,
        ) -> Result<Vec<LifecycleEvent>, DomainError>;

        /// 当前状态：该主体最后一条事件的 `to`；尚无任何事件时为 `None`
        /// （如批次档案已建但 `Created → Produced` 尚未发生——建档本身不是迁移）。
        async fn current_state(
            &self,
            ctx: &mut Self::Context,
            subject: &SubjectRef,
        ) -> Result<Option<LifecycleState>, DomainError>;
    }

    /// 状态变更上链锚定端口（infra 实现：InProcessLedger / alloy，Task 18/26）。
    ///
    /// 将每次生命周期状态变更以事件形式写入账本，供链下/链上核验方对账；
    /// 监管强制路径（召回/销毁）的锚定记录尤其关键。
    #[async_trait]
    pub trait LifecycleAnchorPort: Send + Sync {
        /// 锚定一次状态变更：主体、前后状态与原因上链。
        async fn anchor_change(
            &self,
            subject: &SubjectRef,
            from: LifecycleState,
            to: LifecycleState,
            reason: Option<&str>,
        ) -> Result<(), DomainError>;
    }
}

#[cfg(test)]
mod tests {
    use super::ports::{LifecycleAnchorPort, LifecycleRepository};
    use super::*;
    use crate::shared::{AssetId, BatchId, DomainError, IntentId, SubjectRef};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::future::Future;

    // ---- 内存仓储：锁定端口形状，并作为存储适配器的参考实现 ----

    #[derive(Default)]
    struct MemStore {
        events: Vec<LifecycleEvent>,
    }

    struct MemRepo;

    fn subject_label(subject: &SubjectRef) -> String {
        match subject {
            SubjectRef::Batch(id) => format!("batch:{id}"),
            SubjectRef::Asset(id) => format!("asset:{id}"),
        }
    }

    #[async_trait]
    impl LifecycleRepository for MemRepo {
        type Context = MemStore;

        async fn append(
            &self,
            ctx: &mut Self::Context,
            event: &LifecycleEvent,
        ) -> Result<(), DomainError> {
            // 幂等：同一事件 ID 不重复落库
            if ctx.events.iter().any(|e| e.id == event.id) {
                return Ok(());
            }
            ctx.events.push(event.clone());
            Ok(())
        }

        async fn history(
            &self,
            ctx: &mut Self::Context,
            subject: &SubjectRef,
        ) -> Result<Vec<LifecycleEvent>, DomainError> {
            Ok(ctx
                .events
                .iter()
                .filter(|e| &e.subject == subject)
                .cloned()
                .collect())
        }

        async fn current_state(
            &self,
            ctx: &mut Self::Context,
            subject: &SubjectRef,
        ) -> Result<Option<LifecycleState>, DomainError> {
            Ok(ctx
                .events
                .iter()
                .rev()
                .find(|e| &e.subject == subject)
                .map(|e| e.to))
        }
    }

    /// 内存锚定 fake：记录调用序列供断言；字段须 Send+Sync 以满足端口约束。
    #[derive(Default)]
    struct MemAnchor {
        log: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl LifecycleAnchorPort for MemAnchor {
        async fn anchor_change(
            &self,
            subject: &SubjectRef,
            from: LifecycleState,
            to: LifecycleState,
            reason: Option<&str>,
        ) -> Result<(), DomainError> {
            self.log.lock().unwrap().push(format!(
                "anchor:{}:{from}->{to}:{}",
                subject_label(subject),
                reason.unwrap_or("-")
            ));
            Ok(())
        }
    }

    /// 极简 block_on（与 credential 同款）：内存 fake 的 future 永远就绪，
    /// noop waker 即足够；领域层禁止引入 tokio 等运行时依赖，测试自带最小驱动器。
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

    fn make_event(
        id: &str,
        subject: &SubjectRef,
        from: LifecycleState,
        to: LifecycleState,
    ) -> LifecycleEvent {
        LifecycleEvent::new(
            id,
            subject.clone(),
            from,
            to,
            None,
            IntentId::generate(),
            None,
            None,
            fixed_time(),
        )
        .expect("合法迁移的事件构造应成功")
    }

    #[test]
    fn lifecycle_repository_port_roundtrips_events_and_state() {
        let repo = MemRepo;
        let mut ctx = MemStore::default();
        let subject = SubjectRef::Batch(BatchId::new("b-100"));

        // 空历史：current_state 为 None，history 为空
        let state = block_on(repo.current_state(&mut ctx, &subject)).expect("查询不应报错");
        assert_eq!(state, None);
        let history = block_on(repo.history(&mut ctx, &subject)).expect("查询不应报错");
        assert!(history.is_empty());

        // 追加 Created→Produced、Produced→InWarehouse 两段迁移
        let e1 = make_event(
            "evt-101",
            &subject,
            LifecycleState::Created,
            LifecycleState::Produced,
        );
        let e2 = make_event(
            "evt-102",
            &subject,
            LifecycleState::Produced,
            LifecycleState::InWarehouse,
        );
        block_on(repo.append(&mut ctx, &e1)).expect("append 应成功");
        block_on(repo.append(&mut ctx, &e2)).expect("append 应成功");

        // history 按追加序返回；current_state 取最后一段迁移的 to
        let history = block_on(repo.history(&mut ctx, &subject)).expect("查询不应报错");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0], e1);
        assert_eq!(history[1], e2);
        let state = block_on(repo.current_state(&mut ctx, &subject)).expect("查询不应报错");
        assert_eq!(state, Some(LifecycleState::InWarehouse));

        // 幂等：重复 append 同一事件不产生新记录
        block_on(repo.append(&mut ctx, &e1)).expect("重复 append 应幂等成功");
        let history = block_on(repo.history(&mut ctx, &subject)).expect("查询不应报错");
        assert_eq!(history.len(), 2);

        // 其他主体互不干扰
        let other = SubjectRef::Asset(AssetId::new("a-200"));
        let other_history = block_on(repo.history(&mut ctx, &other)).expect("查询不应报错");
        assert!(other_history.is_empty(), "其他主体不应看到 b-100 的事件");
    }

    #[test]
    fn lifecycle_anchor_port_records_changes() {
        let anchor = MemAnchor::default();
        let subject = SubjectRef::Batch(BatchId::new("b-300"));

        block_on(anchor.anchor_change(
            &subject,
            LifecycleState::Created,
            LifecycleState::Produced,
            Some("产线下线"),
        ))
        .expect("锚定应成功");
        // 监管强制路径同样可锚定，无原因时占位符为 "-"
        block_on(anchor.anchor_change(
            &subject,
            LifecycleState::Produced,
            LifecycleState::Recalled,
            None,
        ))
        .expect("锚定应成功");

        let log = anchor.log.lock().unwrap().join("\n");
        assert!(
            log.contains("anchor:batch:b-300:created->produced:产线下线"),
            "实际日志：{log}"
        );
        assert!(
            log.contains("anchor:batch:b-300:produced->recalled:-"),
            "实际日志：{log}"
        );
    }

    /// 编译期哨兵（与 identity / credential 同款）：`R::Context: Send`
    /// 必须由端口声明本身提供。
    fn requires_context_send<R: LifecycleRepository>(ctx: R::Context) {
        fn needs_send<T: Send>(_: T) {}
        needs_send(ctx);
    }

    #[test]
    fn port_context_must_be_send() {
        requires_context_send::<MemRepo>(MemStore::default());
    }
}
