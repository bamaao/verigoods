//! 凭证状态枚举（CredStatus）。
//!
//! 签发即 [`CredStatus::Valid`]；签发方可在 有效/暂停 间切换或终局撤销。
//! [`CredStatus::Expired`] 为终态，由外部批量任务按 `expires_at` 落库
//! （见 [`crate::credential::vc::VerifiableCredential`] 的说明）。

use serde::{Deserialize, Serialize};

/// 可验证凭证的生命周期状态。
///
/// serde 序列化为小写蛇形：`"valid"` / `"suspended"` / `"revoked"` / `"expired"`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredStatus {
    /// 有效。
    Valid,
    /// 已暂停（临时停用，可恢复为有效）。
    Suspended,
    /// 已撤销（终态，不可迁出）。
    Revoked,
    /// 已过期（终态，不可迁出；由批量任务依据 expires_at 落库）。
    Expired,
}

impl CredStatus {
    /// snake_case 名称，与 serde 序列化结果一致。
    pub fn as_str(&self) -> &'static str {
        match self {
            CredStatus::Valid => "valid",
            CredStatus::Suspended => "suspended",
            CredStatus::Revoked => "revoked",
            CredStatus::Expired => "expired",
        }
    }

    /// 中文名称，用于面向用户的错误信息与审计日志。
    pub fn zh_name(&self) -> &'static str {
        match self {
            CredStatus::Valid => "有效",
            CredStatus::Suspended => "已暂停",
            CredStatus::Revoked => "已撤销",
            CredStatus::Expired => "已过期",
        }
    }
}

impl std::fmt::Display for CredStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_as_lowercase_snake_case() {
        // 四个变体的线上格式逐一断言
        assert_eq!(
            serde_json::to_string(&CredStatus::Valid).unwrap(),
            "\"valid\""
        );
        assert_eq!(
            serde_json::to_string(&CredStatus::Suspended).unwrap(),
            "\"suspended\""
        );
        assert_eq!(
            serde_json::to_string(&CredStatus::Revoked).unwrap(),
            "\"revoked\""
        );
        assert_eq!(
            serde_json::to_string(&CredStatus::Expired).unwrap(),
            "\"expired\""
        );
    }

    #[test]
    fn deserializes_from_lowercase_snake_case() {
        let back: CredStatus = serde_json::from_str("\"valid\"").expect("应可反序列化");
        assert_eq!(back, CredStatus::Valid);
        let back: CredStatus = serde_json::from_str("\"suspended\"").expect("应可反序列化");
        assert_eq!(back, CredStatus::Suspended);
        let back: CredStatus = serde_json::from_str("\"revoked\"").expect("应可反序列化");
        assert_eq!(back, CredStatus::Revoked);
        let back: CredStatus = serde_json::from_str("\"expired\"").expect("应可反序列化");
        assert_eq!(back, CredStatus::Expired);
    }

    #[test]
    fn rejects_unknown_status_string() {
        let err =
            serde_json::from_str::<CredStatus>("\"active\"").expect_err("未知状态字符串必须被拒绝");
        assert!(err.is_data(), "应为 serde 数据错误：{err}");
    }

    #[test]
    fn roundtrip_preserves_every_variant() {
        for status in [
            CredStatus::Valid,
            CredStatus::Suspended,
            CredStatus::Revoked,
            CredStatus::Expired,
        ] {
            let text = serde_json::to_string(&status).unwrap();
            let back: CredStatus = serde_json::from_str(&text).expect("往返应成功");
            assert_eq!(back, status);
        }
    }

    #[test]
    fn as_str_and_display_match_serde_names() {
        for status in [
            CredStatus::Valid,
            CredStatus::Suspended,
            CredStatus::Revoked,
            CredStatus::Expired,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, format!("\"{}\"", status.as_str()));
            assert_eq!(status.to_string(), status.as_str());
        }
    }

    #[test]
    fn zh_names_are_distinct_and_non_empty() {
        let names: Vec<&str> = [
            CredStatus::Valid,
            CredStatus::Suspended,
            CredStatus::Revoked,
            CredStatus::Expired,
        ]
        .iter()
        .map(|s| s.zh_name())
        .collect();
        for name in &names {
            assert!(!name.is_empty(), "中文名不应为空");
        }
        // 去重后数量不变 → 中文名互不相同（错误信息可区分）
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "中文名应互不相同：{names:?}");
    }
}
