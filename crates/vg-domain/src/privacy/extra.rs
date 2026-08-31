//! 加密附加数据（EncryptedExtraData）。

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// 监管可解密的附加数据密文。
///
/// 内容为 `ECIES(view_pub){ from, to, asset, ts }`——用监管域的 view 公钥
/// 做 ECIES 加密的转移元数据，持有对应 view 私钥的监管方即可解密审计
/// （加解密实现属 vg-infra-crypto，Task 10）。
///
/// 领域层不校验密文结构（解密属 infra），serde 以透明 hex 字符串往返。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncryptedExtraData(pub Vec<u8>);

impl Serialize for EncryptedExtraData {
    /// 序列化为 hex 字符串（与 bytea 风格字段一致）。
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for EncryptedExtraData {
    /// 从 hex 字符串反序列化；非法 hex 拒绝，长度不作限制（密文由 infra 定义）。
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transparent_hex_roundtrip() {
        let data = EncryptedExtraData(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let json = serde_json::to_string(&data).unwrap();
        assert_eq!(json, "\"deadbeef\"");
        let back: EncryptedExtraData = serde_json::from_str(&json).unwrap();
        assert_eq!(back, data);

        // 空密文同样可往返
        let empty = EncryptedExtraData(Vec::new());
        let json = serde_json::to_string(&empty).unwrap();
        assert_eq!(json, "\"\"");
        let back: EncryptedExtraData = serde_json::from_str(&json).unwrap();
        assert_eq!(back, empty);
    }

    #[test]
    fn rejects_bad_hex() {
        assert!(serde_json::from_str::<EncryptedExtraData>("\"zz!!\"").is_err());
        // 奇数长度 hex 不是合法字节串
        assert!(serde_json::from_str::<EncryptedExtraData>("\"abc\"").is_err());
    }
}
