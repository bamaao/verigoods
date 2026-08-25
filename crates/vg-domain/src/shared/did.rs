//! DID 值对象。
//!
//! VeriGoods 使用自定义 DID 方法 `did:vg:`，例如：
//! - 智能体：`did:vg:agent:9f2c...`
//! - 其他主体：`did:vg:user:<id>`、`did:vg:batch:<id>` 等

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};

use super::errors::DomainError;

/// VeriGoods 去中心化标识符值对象，形如 `did:vg:<method-specific-id>`。
///
/// 反序列化为手写实现并强制走 [`Did::parse`] 校验（与 [`Hash32`](super::hash::Hash32)
/// 的做法一致），确保任何来源的非法 DID 都无法绕过前缀检查进入领域层。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Did(String);

impl Did {
    /// DID 方法前缀。
    pub const PREFIX: &'static str = "did:vg:";

    /// 解析并校验 DID 字符串。
    ///
    /// 要求：以 `did:vg:` 开头且后缀非空；不满足时返回
    /// [`DomainError::InvalidInput`]。不做更严格的字符集校验（由上层按需收紧）。
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        if !raw.starts_with(Self::PREFIX) {
            return Err(DomainError::InvalidInput(format!(
                "DID 必须以 `{}` 开头",
                Self::PREFIX
            )));
        }
        // `PREFIX` 为纯 ASCII，按字节切片安全
        let suffix = &raw[Self::PREFIX.len()..];
        if suffix.is_empty() {
            return Err(DomainError::InvalidInput("DID 方法专属标识不能为空".into()));
        }
        Ok(Self(raw.to_owned()))
    }

    /// 以字符串形式查看 DID。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 是否为智能体 DID（形如 `did:vg:agent:<...>`）。
    pub fn is_agent(&self) -> bool {
        self.0.starts_with("did:vg:agent:")
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Did {
    type Err = DomainError;

    /// 委托 [`Did::parse`]，使 `"did:vg:x".parse::<Did>()` 可用。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl<'de> Deserialize<'de> for Did {
    /// 从字符串反序列化；强制经过 [`Did::parse`] 校验，
    /// 非法输入映射为 serde 数据错误而非静默通过。
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Did::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_did() {
        let did = Did::parse("did:vg:agent:abc123").expect("合法 DID 应解析成功");
        assert_eq!(did.as_str(), "did:vg:agent:abc123");
        assert_eq!(did.to_string(), "did:vg:agent:abc123");

        // Clone 与相等性语义
        let cloned = did.clone();
        assert_eq!(cloned, did);
    }

    #[test]
    fn rejects_wrong_prefix() {
        for bad in [
            "did:web:example.com",
            "vg:agent:x",
            "",
            "DID:VG:x",
            "did:vgx:abc",
        ] {
            let err = Did::parse(bad).expect_err("非法前缀应被拒绝");
            assert!(
                matches!(err, DomainError::InvalidInput(_)),
                "实际错误：{err:?}"
            );
        }
    }

    #[test]
    fn rejects_empty_suffix() {
        let err = Did::parse("did:vg:").expect_err("空前缀应被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)));
    }

    #[test]
    fn is_agent_detection() {
        assert!(Did::parse("did:vg:agent:xyz").unwrap().is_agent());
        assert!(!Did::parse("did:vg:user:xyz").unwrap().is_agent());
        // 仅是方法段为 agent 前缀字样但缺少分隔符时不算智能体 DID
        assert!(!Did::parse("did:vg:agentfoo").unwrap().is_agent());
    }

    #[test]
    fn serde_serializes_as_plain_string() {
        let did = Did::parse("did:vg:agent:abc123").unwrap();
        let json = serde_json::to_string(&did).expect("序列化应成功");
        assert_eq!(json, "\"did:vg:agent:abc123\"");

        let back: Did = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(back, did);
    }

    #[test]
    fn deserialization_rejects_invalid_did() {
        // 回归测试：此前 #[serde(transparent)] 派生会绕过 parse 的前缀校验，
        // 导致 "not-a-did" 这类垃圾输入也能反序列化成 Did。
        let err = serde_json::from_str::<Did>("\"not-a-did\"")
            .expect_err("非法前缀的 DID 反序列化必须失败");
        assert!(err.is_data(), "应为数据错误：{err}");
        // 前缀正确但后缀为空、以及空字符串，同样必须拒绝
        assert!(serde_json::from_str::<Did>("\"did:vg:\"").is_err());
        assert!(serde_json::from_str::<Did>("\"\"").is_err());
    }

    #[test]
    fn hash_and_eq_semantics_for_map_keys() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Did::parse("did:vg:batch:b1").unwrap());
        assert!(set.contains(&Did::parse("did:vg:batch:b1").unwrap()));
        assert!(!set.contains(&Did::parse("did:vg:batch:b2").unwrap()));
    }

    #[test]
    fn from_str_delegates_to_parse() {
        let did: Did = "did:vg:agent:z9".parse().expect("FromStr 应委托 parse");
        assert_eq!(did.as_str(), "did:vg:agent:z9");
        // 非法输入的错误同样透传
        let err = "garbage".parse::<Did>().expect_err("非法 DID 应报错");
        assert!(matches!(err, DomainError::InvalidInput(_)));
    }
}
