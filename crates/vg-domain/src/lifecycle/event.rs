//! 商品生命周期事件：一次状态变更的不可变事实记录。
//!
//! [`LifecycleEvent`] 是 lifecycle 上下文的核心写模型：仓储端口
//! [`super::ports::LifecycleRepository`] 以追加方式持久化它，
//! 上链锚定端口 [`super::ports::LifecycleAnchorPort`] 将其变更对对外锚定。
//!
//! 构造入口 [`LifecycleEvent::new`] 在构造时即校验状态机合法性
//! （[`crate::lifecycle::state::assert_transition`]），非法迁移的事件
//! 不允许存在——领域不变式前置于一切持久化。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::shared::{DomainError, IntentId, ProofId, SubjectRef};

use super::state::{assert_transition, LifecycleState};

/// 一次商品生命周期状态变更事件。
///
/// 字段公开：事件是不可变的事实记录（append-only），无内部状态需要保护；
/// 合法性由构造入口保证，绕过构造手工拼装属于调用方自担的越权行为。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleEvent {
    /// 事件标识符（幂等键，仓储实现方据此去重）。
    pub id: String,
    /// 变更主体：批次或单品。
    pub subject: SubjectRef,
    /// 迁移前状态。
    pub from: LifecycleState,
    /// 迁移后状态。
    pub to: LifecycleState,
    /// 变更原因（召回公告号、销毁说明等；可为空）。
    pub reason: Option<String>,
    /// 触发本次变更的 Intent 标识符（唯一写入口径回溯）。
    pub intent_id: IntentId,
    /// 关联证明（ZK 证明等）标识符；可为空。
    pub proof_id: Option<ProofId>,
    /// 变更时生效的策略版本；可为空（无策略约束的路径）。
    pub policy_version: Option<u64>,
    /// 变更发生时刻。
    pub at: DateTime<Utc>,
}

impl LifecycleEvent {
    /// 构造一条生命周期事件。
    ///
    /// 约束：`from → to` 必须是状态机合法迁移，否则返回
    /// [`DomainError::InvalidTransition`]（消息携带前后状态的中英文名）。
    #[allow(clippy::too_many_arguments)] // 事件字段即事实全量，聚合成结构体会掩盖缺省语义
    pub fn new(
        id: impl Into<String>,
        subject: SubjectRef,
        from: LifecycleState,
        to: LifecycleState,
        reason: Option<String>,
        intent_id: IntentId,
        proof_id: Option<ProofId>,
        policy_version: Option<u64>,
        at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        // 领域不变式：非法迁移的事件不允许诞生
        assert_transition(from, to)?;
        Ok(Self {
            id: id.into(),
            subject,
            from,
            to,
            reason,
            intent_id,
            proof_id,
            policy_version,
            at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::{AssetId, BatchId};
    use chrono::TimeZone;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 12, 0, 0).unwrap()
    }

    fn batch(id: &str) -> SubjectRef {
        SubjectRef::Batch(BatchId::new(id))
    }

    fn make_event(from: LifecycleState, to: LifecycleState) -> Result<LifecycleEvent, DomainError> {
        LifecycleEvent::new(
            "evt-001",
            batch("b-001"),
            from,
            to,
            Some("产线下线".into()),
            IntentId::new("it-001"),
            Some(ProofId::new("pf-001")),
            Some(1),
            fixed_time(),
        )
    }

    // ---- 合法构造 ----

    #[test]
    fn valid_construction_carries_all_fields() {
        let event = make_event(LifecycleState::Created, LifecycleState::Produced)
            .expect("Created→Produced 应构造成功");
        assert_eq!(event.id, "evt-001");
        assert_eq!(event.subject, batch("b-001"));
        assert_eq!(event.from, LifecycleState::Created);
        assert_eq!(event.to, LifecycleState::Produced);
        assert_eq!(event.reason.as_deref(), Some("产线下线"));
        assert_eq!(event.intent_id, IntentId::new("it-001"));
        assert_eq!(event.proof_id, Some(ProofId::new("pf-001")));
        assert_eq!(event.policy_version, Some(1));
        assert_eq!(event.at, fixed_time());
    }

    #[test]
    fn happy_path_chain_can_all_be_recorded() {
        // 全链路每一步都能落成事件：建档→生产→检验→可售→售出→持有→转售→召回→销毁
        let chain = [
            (LifecycleState::Created, LifecycleState::Produced),
            (LifecycleState::Produced, LifecycleState::Inspected),
            (LifecycleState::Inspected, LifecycleState::Available),
            (LifecycleState::Available, LifecycleState::Sold),
            (LifecycleState::Sold, LifecycleState::Owned),
            (LifecycleState::Owned, LifecycleState::Resold),
            (LifecycleState::Resold, LifecycleState::Recalled),
            (LifecycleState::Recalled, LifecycleState::Destroyed),
        ];
        for (from, to) in chain {
            let event = LifecycleEvent::new(
                format!("{from:?}-to-{to:?}"),
                SubjectRef::Asset(AssetId::new("a-9")),
                from,
                to,
                None,
                IntentId::generate(),
                None,
                None,
                fixed_time(),
            )
            .unwrap_or_else(|err| panic!("{from:?}→{to:?} 不应被拒绝：{err}"));
            assert_eq!(event.from, from);
            assert_eq!(event.to, to);
            assert_eq!(event.reason, None);
        }
    }

    // ---- 非法迁移拒绝 ----

    #[test]
    fn invalid_transition_is_rejected_with_invalid_transition_error() {
        // 越级跳转
        let err = make_event(LifecycleState::Created, LifecycleState::Sold)
            .expect_err("Created→Sold 必须被拒绝");
        assert!(
            matches!(err, DomainError::InvalidTransition { .. }),
            "实际错误：{err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("非法状态迁移"), "实际消息：{msg}");
        assert!(msg.contains("created") && msg.contains("sold"), "{msg}");
        assert!(msg.contains("创建") && msg.contains("已售出"), "{msg}");

        // 终态出边同样不允许成事
        for (from, to) in [
            (LifecycleState::Expired, LifecycleState::Produced),
            (LifecycleState::Destroyed, LifecycleState::Available),
        ] {
            let err = make_event(from, to).expect_err("终态不允许迁出");
            assert!(
                matches!(err, DomainError::InvalidTransition { .. }),
                "{err:?}"
            );
        }

        // 自迁移不允许
        let err = make_event(LifecycleState::Available, LifecycleState::Available)
            .expect_err("自迁移必须被拒绝");
        assert!(matches!(err, DomainError::InvalidTransition { .. }));
    }

    // ---- serde 往返 ----

    #[test]
    fn json_roundtrip_preserves_all_fields_with_snake_case_states() {
        let event = make_event(LifecycleState::Produced, LifecycleState::InTransit)
            .expect("样例事件应构造成功");

        let text = serde_json::to_string(&event).expect("序列化应成功");
        assert!(
            text.contains("\"from\":\"produced\"") && text.contains("\"to\":\"in_transit\""),
            "状态字段应为小写蛇形：{text}"
        );

        let back: LifecycleEvent = serde_json::from_str(&text).expect("反序列化应成功");
        assert_eq!(back, event, "往返应无损保留全部字段");
    }
}
