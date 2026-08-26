//! 所有权转移记录与保管变更事件。
//!
//! - [`TransferRecord`]：一次所有权转移的不可变事实（append-only），
//!   供 [`super::ports::OwnershipRepository::history`] 审计回放；
//! - [`CustodyUpdate`]：一次保管变更的事件/命令结构，由应用层构造后
//!   交给 [`crate::ownership::CustodyState::apply_update`] 消费。

use serde::{Deserialize, Serialize};

use crate::shared::{Did, SubjectRef};

use chrono::{DateTime, Utc};

/// 一次所有权转移的审计记录。
///
/// 字段公开：与 [`crate::lifecycle::LifecycleEvent`] 同款——事件是不可变的
/// 事实记录，无内部状态需要保护。`transfer_count` / `c2c_count` 为本次
/// 转移**自增后**的计数值（对应合约 `OwnershipTransferred` 事件携带的
/// `transferCount`），用于审计回放时核对计数器连续性。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferRecord {
    /// 记录标识符（幂等键，仓储实现方据此去重；UUIDv7 字符串，
    /// 由 [`OwnershipState::transfer`](crate::ownership::OwnershipState::transfer)
    /// 在领域侧生成，与 [`crate::lifecycle::LifecycleEvent`] 的 `id` 同款先例）。
    pub id: String,
    /// 转移客体：批次或单品。
    pub subject: SubjectRef,
    /// 原所有者。
    pub from: Did,
    /// 新所有者。
    pub to: Did,
    /// 是否为消费者对消费者（C2C）转移。
    pub c2c: bool,
    /// 转移发生时刻。
    pub at: DateTime<Utc>,
    /// 本次转移后的累计转移次数。
    pub transfer_count: u32,
    /// 本次转移后的累计 C2C 转移次数。
    pub c2c_count: u32,
}

/// 一次保管变更的事件/命令结构。
///
/// `from` 为可选前手：`Some(prev)` 表示事件主张"此前由 prev 保管"
/// （乐观并发控制，由消费方校验）；`None` 表示不主张前手（如初始托管登记）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyUpdate {
    /// 保管客体：批次或单品。
    pub subject: SubjectRef,
    /// 事件声称的前任保管人；`None` 表示不主张前手。
    pub from: Option<Did>,
    /// 新保管人。
    pub to: Did,
    /// 变更原因（发货/入库/出库/交接）。
    pub reason: CustodyReason,
}

/// 保管变更原因。
///
/// serde 序列化为小写蛇形：`"ship"` / `"warehouse_in"` 等。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyReason {
    /// 发货（卖方交运）。
    Ship,
    /// 入仓（仓库收货）。
    WarehouseIn,
    /// 出仓（仓库发货）。
    WarehouseOut,
    /// 交接（当面/末端交付）。
    Handover,
}

impl CustodyReason {
    /// snake_case 名称，与 serde 序列化结果一致。
    pub fn as_str(&self) -> &'static str {
        match self {
            CustodyReason::Ship => "ship",
            CustodyReason::WarehouseIn => "warehouse_in",
            CustodyReason::WarehouseOut => "warehouse_out",
            CustodyReason::Handover => "handover",
        }
    }

    /// 中文名称，用于面向用户的错误信息与审计日志。
    pub fn zh_name(&self) -> &'static str {
        match self {
            CustodyReason::Ship => "发货",
            CustodyReason::WarehouseIn => "入仓",
            CustodyReason::WarehouseOut => "出仓",
            CustodyReason::Handover => "交接",
        }
    }
}

impl std::fmt::Display for CustodyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::{AssetId, BatchId};
    use chrono::TimeZone;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 8, 0, 0).unwrap()
    }

    fn alice() -> Did {
        Did::parse("did:vg:user:alice").unwrap()
    }

    fn bob() -> Did {
        Did::parse("did:vg:user:bob").unwrap()
    }

    #[test]
    fn transfer_record_carries_full_audit_fields() {
        let record = TransferRecord {
            id: "01990000-0000-7000-8000-000000000001".to_string(),
            subject: SubjectRef::Asset(AssetId::new("a-rec-1")),
            from: alice(),
            to: bob(),
            c2c: true,
            at: fixed_time(),
            transfer_count: 3,
            c2c_count: 1,
        };
        assert_eq!(record.subject, SubjectRef::Asset(AssetId::new("a-rec-1")));
        assert!(!record.id.is_empty(), "幂等键 id 必须非空");
        assert_eq!(record.from, alice());
        assert_eq!(record.to, bob());
        assert!(record.c2c);
        assert_eq!(record.at, fixed_time());
        assert_eq!((record.transfer_count, record.c2c_count), (3, 1));
    }

    #[test]
    fn transfer_record_serde_roundtrip_for_audit_replay() {
        let record = TransferRecord {
            id: "01990000-0000-7000-8000-000000000002".to_string(),
            subject: SubjectRef::Batch(BatchId::new("b-rec-1")),
            from: alice(),
            to: bob(),
            c2c: true,
            at: fixed_time(),
            transfer_count: 2,
            c2c_count: 1,
        };
        let text = serde_json::to_string(&record).expect("序列化应成功");
        assert!(
            text.contains("\"id\"")
                && text.contains("\"c2c\":true")
                && text.contains("\"from\"")
                && text.contains("\"to\""),
            "字段应为蛇形命名且含幂等键：{text}"
        );
        let back: TransferRecord = serde_json::from_str(&text).expect("反序列化应成功");
        assert_eq!(back, record, "审计回放要求 serde 往返无损");
    }

    #[test]
    fn custody_reason_serializes_snake_case_and_reports_zh_names() {
        let cases = [
            (CustodyReason::Ship, "\"ship\"", "发货"),
            (CustodyReason::WarehouseIn, "\"warehouse_in\"", "入仓"),
            (CustodyReason::WarehouseOut, "\"warehouse_out\"", "出仓"),
            (CustodyReason::Handover, "\"handover\"", "交接"),
        ];
        for (reason, json, zh) in cases {
            assert_eq!(serde_json::to_string(&reason).unwrap(), json);
            assert_eq!(reason.as_str(), json.trim_matches('"'));
            assert_eq!(reason.to_string(), json.trim_matches('"'));
            assert_eq!(reason.zh_name(), zh);

            let back: CustodyReason = serde_json::from_str(json).unwrap();
            assert_eq!(back, reason);
        }
    }
}
