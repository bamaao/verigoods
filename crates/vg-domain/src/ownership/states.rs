//! 所有权与保管的状态值对象。
//!
//! 本模块承载 ownership 上下文的核心不变量：**所有权与保管完全分离**。
//!
//! - [`OwnershipState`]：某主体（批次/单品）的当前所有者与转移计数，
//!   对应合约 [`OwnershipRegistry.Ownership`](https://github.com/VeriGoods/commodity-network-smart-contracts)
//!   结构（ownerDid/acquiredAt/transferCount/c2cCount）；
//! - [`CustodyState`]：某主体的当前保管人，物流域概念，与所有权互不相干。
//!
//! 两者除 `subject` 外字段零交集：转移所有权不改保管人，更新保管不改所有者。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::shared::{Did, DomainError, SubjectRef};

use super::transfer::CustodyUpdate;
use super::transfer::TransferRecord;

/// 某主体的当前所有权状态。
///
/// 字段公开：与 [`crate::commodity::Batch`] 等值聚合一致，合法性由构造入口
/// 与领域方法保证，绕过方法直接改写计数字段属于调用方自担的越权行为。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipState {
    /// 所有客体：批次或单品。
    pub subject: SubjectRef,
    /// 当前所有者 DID。
    pub owner: Did,
    /// 取得所有权的时刻（每次转移刷新，对应合约 `acquiredAt`）。
    pub acquired_at: DateTime<Utc>,
    /// 普通转移总次数（含 C2C，对应合约 `transferCount`）。
    pub transfer_count: u32,
    /// 其中消费者对消费者（C2C）转移次数（对应合约 `c2cCount`）。
    pub c2c_count: u32,
}

impl OwnershipState {
    /// 初始化某主体的所有权档案（对应合约 `OwnershipRegistry.initializeOwner`）。
    ///
    /// 合约侧的 `require(ownerDid == bytes32(0), "owner exists")` 是**对存储的
    /// 唯一性检查**：本模块的 [`OwnershipState`] 是纯值对象，无法感知存储中
    /// 该主体是否已初始化，因此该不变式由仓储端口
    /// [`super::ports::OwnershipRepository::init_owner`] 的唯一约束承载
    /// （同主体重复初始化返回 [`DomainError::AlreadyExists`]）。
    /// 领域侧构造函数只负责产出"计数归零"的初始状态。
    ///
    /// 另注：合约要求初始 owner 非 `bytes32(0)`（零地址）。本项目 [`Did`]
    /// 值对象在构造时强制 `did:vg:` 前缀且后缀非空，零地址不可表示为合法
    /// `Did`，故该检查在此自然满足，无需重复实现。
    pub fn initialize(subject: SubjectRef, owner: Did, at: DateTime<Utc>) -> Self {
        Self {
            subject,
            owner,
            acquired_at: at,
            transfer_count: 0,
            c2c_count: 0,
        }
    }

    /// 将所有权转移给 `to`，返回本次转移的审计记录。
    ///
    /// `at` 为记账时刻，由调用方（应用层）注入——领域层不读取真实时钟。
    ///
    /// 规则：
    /// - 目标不得为当前所有者（自转拒绝，对应合约 `require(toDid != o.ownerDid,
    ///   "invalid target")`）；错误选型为 [`DomainError::InvalidTransition`]：
    ///   合约语义是"目标非法"而非"操作者权限不足"，自转等价于迁移到当前
    ///   状态，与 lifecycle 状态机拒绝自迁移同一裁决口径；[`DomainError::Unauthorized`]
    ///   保留给操作者角色不足场景（合约 `onlyRole` 校验由应用层承担）；
    /// - 目标非零地址的检查同样由 [`Did`] 的构造校验天然满足（见
    ///   [`Self::initialize`] 注释）；
    /// - 任一计数器已达 `u32::MAX` → [`DomainError::InvalidInput`]：
    ///   自增走 `checked_add`，与 commodity 批次合并总量溢出同一先例选型
    ///   （溢出属输入/存量异常而非状态迁移问题）；release 下裸 `+=` 会静默
    ///   回绕，破坏 [`TransferRecord`] 计数的审计连续性；
    ///
    /// 成功后：`owner` 更新、`acquired_at` 刷新为 `at`、`transfer_count`
    /// 自增且 `c2c = true` 时额外自增 `c2c_count`；失败时不产生任何副作用。
    pub fn transfer(
        &mut self,
        to: &Did,
        c2c: bool,
        at: DateTime<Utc>,
    ) -> Result<TransferRecord, DomainError> {
        // 自转拒绝（合约 "invalid target"）：目标等于当前所有者即非法迁移
        if *to == self.owner {
            return Err(DomainError::InvalidTransition {
                from: self.owner.to_string(),
                to: to.to_string(),
            });
        }
        // 计数器溢出守卫：先检查后变更，保证失败时零副作用
        let next_transfer_count = self.transfer_count.checked_add(1).ok_or_else(|| {
            DomainError::InvalidInput(format!(
                "转移计数溢出：transfer_count 已达 {}，拒绝转移",
                u32::MAX
            ))
        })?;
        let next_c2c_count = if c2c {
            self.c2c_count.checked_add(1).ok_or_else(|| {
                DomainError::InvalidInput(format!(
                    "C2C 转移计数溢出：c2c_count 已达 {}，拒绝转移",
                    u32::MAX
                ))
            })?
        } else {
            self.c2c_count
        };
        let from = std::mem::replace(&mut self.owner, to.clone());
        self.acquired_at = at;
        self.transfer_count = next_transfer_count;
        self.c2c_count = next_c2c_count;
        Ok(TransferRecord {
            // 记录 ID 在领域侧生成：`Uuid::now_v7` 是项目允许的 ID 工厂先例
            // （shared::ids IntentId::generate 同款），时间有序利于审计回放；
            // 不改为调用方传参，避免转移 API 被 ID 管理细节污染。仓储侧按该
            // ID 幂等去重（pg 唯一键）。
            id: uuid::Uuid::now_v7().to_string(),
            subject: self.subject.clone(),
            from,
            to: to.clone(),
            c2c,
            at,
            transfer_count: next_transfer_count,
            c2c_count: next_c2c_count,
        })
    }
}

/// 某主体的当前保管状态。
///
/// 保管（custody）是物流域概念：商品在运输/仓储/交接环节的实际控制方。
/// 它与 [`OwnershipState`] 完全独立——转移所有权不代表交出实物保管，
/// 反之亦然；唯一关联是作用于同一个 `subject`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyState {
    /// 保管客体：批次或单品。
    pub subject: SubjectRef,
    /// 当前保管人 DID。
    pub custodian: Did,
    /// 当前保管关系的生效时刻（每次保管变更刷新）。
    pub since: DateTime<Utc>,
}

impl CustodyState {
    /// 建立初始保管关系。
    pub fn new(subject: SubjectRef, custodian: Did, at: DateTime<Utc>) -> Self {
        Self {
            subject,
            custodian,
            since: at,
        }
    }

    /// 应用一次保管变更（消费 [`CustodyUpdate`] 事件）。
    ///
    /// `at` 为记账时刻，由调用方注入；成功后 `custodian = update.to`、
    /// `since = at`。失败时不产生任何副作用。
    ///
    /// 规则：
    /// - `update.subject` 必须与本状态的主体一致，否则
    ///   [`DomainError::InvalidInput`]；
    /// - `update.from` 为 `Some(prev)` 时是事件声称的前手（乐观并发控制），
    ///   必须与当前保管人一致，否则说明事件过期或与并发写入冲突，返回
    ///   [`DomainError::InvalidTransition`]；`None` 表示不主张前手
    ///   （如初始托管登记），跳过该校验；
    /// - 目标不得为当前保管人（自转托管无意义），返回
    ///   [`DomainError::InvalidTransition`]。
    pub fn apply_update(
        &mut self,
        update: &CustodyUpdate,
        at: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        // 事件必须作用于同一主体
        if update.subject != self.subject {
            let label = |s: &SubjectRef| match s {
                SubjectRef::Batch(id) => format!("batch:{id}"),
                SubjectRef::Asset(id) => format!("asset:{id}"),
            };
            return Err(DomainError::InvalidInput(format!(
                "保管更新主体不匹配：状态 {}，事件 {}",
                label(&self.subject),
                label(&update.subject)
            )));
        }
        // 前手校验（乐观并发控制）：Some(prev) 必须与当前保管人一致，
        // 否则说明事件过期或与并发写入冲突
        if let Some(prev) = &update.from {
            if *prev != self.custodian {
                return Err(DomainError::InvalidTransition {
                    from: prev.to_string(),
                    to: format!(
                        "{}（事件前手与当前保管人 {} 不符）",
                        update.to, self.custodian
                    ),
                });
            }
        }
        // 自转托管拒绝：目标等于当前保管人则无意义
        if update.to == self.custodian {
            return Err(DomainError::InvalidTransition {
                from: self.custodian.to_string(),
                to: update.to.to_string(),
            });
        }
        self.custodian = update.to.clone();
        self.since = at;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::{AssetId, BatchId};
    use chrono::TimeZone;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 0, 0, 0).unwrap()
    }

    fn later_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 26, 12, 30, 0).unwrap()
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

    fn owned_by_alice() -> OwnershipState {
        OwnershipState::initialize(batch_subject("b-own-1"), alice(), fixed_time())
    }

    // ---- 所有权：初始化 ----

    #[test]
    fn initialize_produces_zeroed_counters_with_given_owner_and_time() {
        let state = owned_by_alice();
        assert_eq!(state.subject, batch_subject("b-own-1"));
        assert_eq!(state.owner, alice());
        assert_eq!(state.acquired_at, fixed_time());
        assert_eq!(state.transfer_count, 0, "初始普通转移计数应为 0");
        assert_eq!(state.c2c_count, 0, "初始 C2C 转移计数应为 0");
    }

    // ---- 所有权：转移 ----

    #[test]
    fn transfer_moves_owner_refreshes_acquired_at_and_counts() {
        let mut state = owned_by_alice();
        let record = state
            .transfer(&bob(), false, later_time())
            .expect("正常转移应成功");

        assert_eq!(state.owner, bob(), "所有者应变为目标 DID");
        assert_eq!(
            state.acquired_at,
            later_time(),
            "acquired_at 应刷新为本次转移时刻"
        );
        assert_eq!(state.transfer_count, 1, "普通转移应使 transfer_count 自增");
        assert_eq!(state.c2c_count, 0, "非 C2C 转移不得动 c2c_count");
        assert_eq!(record.from, alice());
        assert_eq!(record.to, bob());
        assert!(!record.c2c);
    }

    #[test]
    fn c2c_transfer_additionally_increments_c2c_count() {
        let mut state = owned_by_alice();
        state
            .transfer(&bob(), false, fixed_time())
            .expect("普通转移应成功");
        let record = state
            .transfer(&carol(), true, later_time())
            .expect("C2C 转移应成功");

        assert!(record.c2c);
        assert_eq!(record.transfer_count, 2, "第二次转移后总数应为 2");
        assert_eq!(record.c2c_count, 1, "仅 C2C 转移使 c2c_count 自增到 1");
        assert_eq!(state.transfer_count, 2);
        assert_eq!(state.c2c_count, 1);
    }

    #[test]
    fn transfer_stamps_unique_uuid_v7_ids_on_records() {
        let mut state = owned_by_alice();
        let r1 = state
            .transfer(&bob(), false, fixed_time())
            .expect("第一次转移应成功");
        let r2 = state
            .transfer(&carol(), true, later_time())
            .expect("第二次转移应成功");

        // 每条记录都携带幂等键，且互不相同（仓储据此去重）
        for r in [&r1, &r2] {
            assert_eq!(r.id.len(), 36, "应为标准连字符 UUID 形态：{}", r.id);
            // UUIDv7 版本位：第 14 个字符（第三组首字符）恒为 '7'
            assert_eq!(r.id.as_bytes()[14], b'7', "应为 v7 UUID：{}", r.id);
        }
        assert_ne!(r1.id, r2.id, "两次转移的记录 ID 必须唯一");
    }

    #[test]
    fn self_transfer_is_rejected_as_invalid_transition_without_side_effects() {
        let mut state = owned_by_alice();
        let err = state
            .transfer(&alice(), false, later_time())
            .expect_err("转给当前所有者自己必须被拒绝（合约 invalid target）");
        assert!(
            matches!(&err, DomainError::InvalidTransition { from, to }
                if from == alice().as_str() && to == alice().as_str()),
            "实际错误：{err:?}"
        );
        // 失败不得产生副作用
        assert_eq!(state.owner, alice());
        assert_eq!(state.acquired_at, fixed_time());
        assert_eq!((state.transfer_count, state.c2c_count), (0, 0));
    }

    // ---- 所有权：计数器溢出守卫 ----

    #[test]
    fn transfer_overflowing_transfer_count_is_rejected_without_side_effects() {
        // 存量值可经 Deserialize 载入，u32::MAX 必须真实可达：一次转移即触发溢出
        let mut state = OwnershipState {
            subject: batch_subject("b-ovf-1"),
            owner: alice(),
            acquired_at: fixed_time(),
            transfer_count: u32::MAX,
            c2c_count: 3,
        };
        let err = state
            .transfer(&bob(), false, later_time())
            .expect_err("transfer_count 溢出必须被拒绝而非回绕");
        assert!(
            matches!(&err, DomainError::InvalidInput(msg) if msg.contains("溢出")),
            "与 commodity 批次合并总量溢出同一先例选型，实际错误：{err:?}"
        );
        // 失败零副作用：所有字段纹丝不动
        assert_eq!(state.owner, alice());
        assert_eq!(state.acquired_at, fixed_time());
        assert_eq!(state.transfer_count, u32::MAX);
        assert_eq!(state.c2c_count, 3);
    }

    #[test]
    fn c2c_overflowing_c2c_count_is_rejected_without_side_effects() {
        let mut state = OwnershipState {
            subject: batch_subject("b-ovf-2"),
            owner: alice(),
            acquired_at: fixed_time(),
            transfer_count: 5,
            c2c_count: u32::MAX,
        };
        let err = state
            .transfer(&bob(), true, later_time())
            .expect_err("c2c=true 且 c2c_count 溢出必须被拒绝而非回绕");
        assert!(
            matches!(&err, DomainError::InvalidInput(msg) if msg.contains("溢出")),
            "实际错误：{err:?}"
        );
        // 失败零副作用：owner / acquired_at / 两个计数器全部不变
        assert_eq!(state.owner, alice());
        assert_eq!(state.acquired_at, fixed_time());
        assert_eq!(state.transfer_count, 5);
        assert_eq!(state.c2c_count, u32::MAX);
    }

    #[test]
    fn ownership_state_serde_roundtrip_preserves_fields() {
        let mut state = owned_by_alice();
        state
            .transfer(&bob(), true, later_time())
            .expect("转移应成功");
        let text = serde_json::to_string(&state).expect("序列化应成功");
        let back: OwnershipState = serde_json::from_str(&text).expect("反序列化应成功");
        assert_eq!(back, state, "serde 往返后字段必须完全一致");
    }

    // ---- 保管：更新 ----

    #[test]
    fn custody_update_replaces_custodian_and_resets_since() {
        let mut custody = CustodyState::new(batch_subject("b-own-1"), alice(), fixed_time());

        // 带前手的正常交接：from 主张的前手与当前保管人一致
        let update = CustodyUpdate {
            subject: batch_subject("b-own-1"),
            from: Some(alice()),
            to: bob(),
            reason: crate::ownership::CustodyReason::Ship,
        };
        custody
            .apply_update(&update, later_time())
            .expect("合法保管更新应成功");

        assert_eq!(custody.custodian, bob(), "保管人应更新为新 DID");
        assert_eq!(custody.since, later_time(), "since 应重置为本次更新时刻");
    }

    #[test]
    fn custody_update_allows_none_from_for_initial_registration() {
        let mut custody = CustodyState::new(batch_subject("b-own-2"), alice(), fixed_time());
        let update = CustodyUpdate {
            subject: batch_subject("b-own-2"),
            from: None,
            to: bob(),
            reason: crate::ownership::CustodyReason::WarehouseIn,
        };
        custody
            .apply_update(&update, later_time())
            .expect("None 前手应跳过校验");
        assert_eq!(custody.custodian, bob());
    }

    #[test]
    fn custody_update_rejects_mismatched_subject() {
        let mut custody = CustodyState::new(batch_subject("b-own-3"), alice(), fixed_time());
        let update = CustodyUpdate {
            subject: SubjectRef::Asset(AssetId::new("a-other")),
            from: Some(alice()),
            to: bob(),
            reason: crate::ownership::CustodyReason::Handover,
        };
        let err = custody
            .apply_update(&update, later_time())
            .expect_err("跨主体的保管更新必须被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)), "{err:?}");
        // 失败不得产生副作用
        assert_eq!(custody.custodian, alice());
    }

    #[test]
    fn custody_update_rejects_stale_previous_custodian_without_side_effects() {
        let mut custody = CustodyState::new(batch_subject("b-own-4"), bob(), fixed_time());
        // 事件声称前手是 alice，但当前保管人是 bob：过期/并发冲突事件
        let update = CustodyUpdate {
            subject: batch_subject("b-own-4"),
            from: Some(alice()),
            to: carol(),
            reason: crate::ownership::CustodyReason::WarehouseOut,
        };
        let err = custody
            .apply_update(&update, later_time())
            .expect_err("前手不符的事件必须被拒绝");
        assert!(
            matches!(err, DomainError::InvalidTransition { .. }),
            "实际错误：{err:?}"
        );
        assert_eq!(custody.custodian, bob(), "失败的更新不得改变保管人");
        assert_eq!(custody.since, fixed_time());
    }

    #[test]
    fn custody_reassignment_to_current_custodian_is_rejected() {
        let mut custody = CustodyState::new(batch_subject("b-own-5"), alice(), fixed_time());
        let update = CustodyUpdate {
            subject: batch_subject("b-own-5"),
            from: Some(alice()),
            to: alice(),
            reason: crate::ownership::CustodyReason::Handover,
        };
        let err = custody
            .apply_update(&update, later_time())
            .expect_err("把保管转给当前保管人自己必须被拒绝");
        assert!(
            matches!(err, DomainError::InvalidTransition { .. }),
            "{err:?}"
        );
        assert_eq!(custody.since, fixed_time(), "自转不得刷新 since");
    }

    #[test]
    fn custody_state_serde_roundtrip_preserves_fields() {
        let custody = CustodyState::new(batch_subject("b-own-6"), bob(), fixed_time());
        let text = serde_json::to_string(&custody).expect("序列化应成功");
        let back: CustodyState = serde_json::from_str(&text).expect("反序列化应成功");
        assert_eq!(back, custody);
    }
}
