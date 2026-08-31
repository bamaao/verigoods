//! 监管域：某个监管机构对特定辖区/商品类型集合的管辖声明。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::credential::CredentialSchema;
use crate::shared::Did;

/// 监管域（数据结构）：一个监管主体在指定辖区内、对一组商品类型的管辖范围。
///
/// 纯数据载体（无行为方法）：域的有效性判断由上层按 `effective_from`
/// 结合具体业务场景决定，领域层不做过度设计。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegulatoryDomain {
    /// 监管域标识符（如 `"vg:domain:cn-food@v1"`）。
    pub domain_id: String,
    /// 监管机构 DID。
    pub authority: Did,
    /// 辖区（如 `"CN"` / `"EU"`）。
    pub jurisdiction: String,
    /// 管辖的商品类型集合。
    pub product_types: Vec<String>,
    /// 该域适用的凭证模式集合。
    pub credential_schemas: Vec<CredentialSchema>,
    /// 生效起始时刻。
    pub effective_from: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn sample_domain() -> RegulatoryDomain {
        RegulatoryDomain {
            domain_id: "vg:domain:cn-food@v1".into(),
            authority: Did::parse("did:vg:user:reg-001").unwrap(),
            jurisdiction: "CN".into(),
            product_types: vec!["food".into(), "beverage".into()],
            credential_schemas: vec![CredentialSchema {
                id: "vg:schema:food-safety@v1".into(),
                ctype: crate::credential::CredentialType::FoodSafetyInspection,
                required_claims: vec!["result".into()],
            }],
            effective_from: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        }
    }

    #[test]
    fn regulatory_domain_serializes_and_roundtrips() {
        let domain = sample_domain();
        let text = serde_json::to_string(&domain).expect("序列化应成功");
        let back: RegulatoryDomain = serde_json::from_str(&text).expect("反序列化应成功");
        assert_eq!(back, domain);
        // 关键字段在 JSON 中可见
        assert!(text.contains("\"CN\""));
        assert!(text.contains("vg:schema:food-safety@v1"));
    }
}
