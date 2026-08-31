//! ABAC：基于属性（角色 × 辖区 × 数据类别）的访问裁决。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::shared::Did;

use super::policy::PolicyEngine;

/// 访问主体角色。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// 企业（生产/流通环节参与方）。
    Enterprise,
    /// 监管机构。
    Regulator,
    /// 消费者。
    Consumer,
    /// 审计方。
    Auditor,
    /// 物流方。
    Logistics,
}

impl Role {
    /// snake_case 名称，与 serde 序列化结果一致。
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Enterprise => "enterprise",
            Role::Regulator => "regulator",
            Role::Consumer => "consumer",
            Role::Auditor => "auditor",
            Role::Logistics => "logistics",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 被访问的数据类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataType {
    /// 价格数据。
    Price,
    /// 合同数据。
    Contract,
    /// 完整报告。
    ReportFull,
    /// 身份 PII（个人身份信息）。
    IdentityPii,
    /// 生命周期公开数据。
    LifecyclePublic,
}

impl DataType {
    /// snake_case 名称，与 serde 序列化结果一致。
    pub fn as_str(&self) -> &'static str {
        match self {
            DataType::Price => "price",
            DataType::Contract => "contract",
            DataType::ReportFull => "report_full",
            DataType::IdentityPii => "identity_pii",
            DataType::LifecyclePublic => "lifecycle_public",
        }
    }
}

impl std::fmt::Display for DataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ABAC 裁决请求。
///
/// 辖区拆分为两字段：`subject_jurisdiction`（访问者辖区）与
/// `data_jurisdiction`（数据辖区）——监管者只在**本辖区**拥有全量访问权，
/// 跨辖区必须拒绝，单字段无法表达该比较。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbacRequest {
    /// 访问主体 DID。
    pub subject: Did,
    /// 主体角色。
    pub role: Role,
    /// 访问者辖区。
    pub subject_jurisdiction: String,
    /// 数据辖区。
    pub data_jurisdiction: String,
    /// 数据所属商品类型（预留属性维度）。
    pub product_type: String,
    /// 被访问数据类别。
    pub data: DataType,
    /// 请求时刻（time 窗口维度占位，当前矩阵不依赖时间）。
    pub now: DateTime<Utc>,
}

impl PolicyEngine {
    /// ABAC 裁决：role × dataType 访问矩阵，Regulator 附加辖区相等条件。
    ///
    /// 矩阵：
    /// - Enterprise：Price/Contract/ReportFull/LifecyclePublic 允许，IdentityPii 拒绝；
    /// - Regulator：本辖区（两辖区相等）全部允许；跨辖区拒绝；
    /// - Consumer：仅 LifecyclePublic；
    /// - Auditor：ReportFull/LifecyclePublic；
    /// - Logistics：仅 LifecyclePublic。
    pub fn abac_check(req: &AbacRequest) -> bool {
        use DataType as D;
        use Role as R;
        match (req.role, req.data) {
            (R::Enterprise, D::IdentityPii) => false,
            (R::Enterprise, _) => true,
            (R::Regulator, _) => req.subject_jurisdiction == req.data_jurisdiction,
            (R::Consumer, D::LifecyclePublic)
            | (R::Logistics, D::LifecyclePublic)
            | (R::Auditor, D::ReportFull)
            | (R::Auditor, D::LifecyclePublic) => true,
            (R::Consumer, _) | (R::Logistics, _) | (R::Auditor, _) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn req(role: Role, data: DataType, subj_j: &str, data_j: &str) -> AbacRequest {
        AbacRequest {
            subject: Did::parse("did:vg:user:actor-001").unwrap(),
            role,
            subject_jurisdiction: subj_j.into(),
            data_jurisdiction: data_j.into(),
            product_type: "food".into(),
            data,
            now: Utc.with_ymd_and_hms(2026, 8, 30, 0, 0, 0).unwrap(),
        }
    }

    #[test]
    fn full_role_by_datatype_matrix() {
        use DataType as D;
        use Role as R;
        // (role, dataType, 同辖区时是否允许)
        let matrix: &[(Role, DataType, bool)] = &[
            (R::Enterprise, D::Price, true),
            (R::Enterprise, D::Contract, true),
            (R::Enterprise, D::ReportFull, true),
            (R::Enterprise, D::LifecyclePublic, true),
            (R::Enterprise, D::IdentityPii, false),
            (R::Regulator, D::Price, true),
            (R::Regulator, D::Contract, true),
            (R::Regulator, D::ReportFull, true),
            (R::Regulator, D::IdentityPii, true),
            (R::Regulator, D::LifecyclePublic, true),
            (R::Consumer, D::LifecyclePublic, true),
            (R::Consumer, D::Price, false),
            (R::Consumer, D::Contract, false),
            (R::Consumer, D::ReportFull, false),
            (R::Consumer, D::IdentityPii, false),
            (R::Auditor, D::ReportFull, true),
            (R::Auditor, D::LifecyclePublic, true),
            (R::Auditor, D::Price, false),
            (R::Auditor, D::Contract, false),
            (R::Auditor, D::IdentityPii, false),
            (R::Logistics, D::LifecyclePublic, true),
            (R::Logistics, D::Price, false),
            (R::Logistics, D::Contract, false),
            (R::Logistics, D::ReportFull, false),
            (R::Logistics, D::IdentityPii, false),
        ];
        for &(role, data, allowed) in matrix {
            assert_eq!(
                PolicyEngine::abac_check(&req(role, data, "CN", "CN")),
                allowed,
                "{role} × {data} 应为 {allowed}"
            );
        }
    }

    #[test]
    fn regulator_same_jurisdiction_allowed_cross_jurisdiction_denied() {
        use DataType as D;
        // 本辖区：全部数据类别允许（含 PII）
        for data in [
            D::Price,
            D::Contract,
            D::ReportFull,
            D::IdentityPii,
            D::LifecyclePublic,
        ] {
            assert!(
                PolicyEngine::abac_check(&req(Role::Regulator, data, "CN", "CN")),
                "本辖区 {data} 应允许"
            );
        }
        // 跨辖区：全部数据类别拒绝
        for data in [
            D::Price,
            D::Contract,
            D::ReportFull,
            D::IdentityPii,
            D::LifecyclePublic,
        ] {
            assert!(
                !PolicyEngine::abac_check(&req(Role::Regulator, data, "CN", "EU")),
                "跨辖区 {data} 应拒绝"
            );
        }
    }

    #[test]
    fn enums_serialize_snake_case() {
        assert_eq!(
            serde_json::to_string(&Role::Logistics).unwrap(),
            "\"logistics\""
        );
        assert_eq!(
            serde_json::to_string(&DataType::IdentityPii).unwrap(),
            "\"identity_pii\""
        );
        assert_eq!(
            serde_json::to_string(&DataType::ReportFull).unwrap(),
            "\"report_full\""
        );
    }

    #[test]
    fn abac_request_roundtrips_through_json() {
        let request = req(Role::Auditor, DataType::ReportFull, "CN", "CN");
        let text = serde_json::to_string(&request).expect("序列化应成功");
        let back: AbacRequest = serde_json::from_str(&text).expect("反序列化应成功");
        assert_eq!(back, request);
    }
}
