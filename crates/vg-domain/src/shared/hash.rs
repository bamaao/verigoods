//! 32 字节哈希值对象，对应合约层 `bytes32`。

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Keccak256};

use super::errors::DomainError;

/// 32 字节哈希（Keccak-256 摘要、承诺值、合约 bytes32 参数的领域表示）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash32([u8; 32]);

impl Hash32 {
    /// 全零哈希，对应合约 `bytes32(0)` 哨兵语义。
    pub const ZERO: Hash32 = Hash32([0u8; 32]);

    /// 由原始 32 字节构造（供 infra 侧哈希器实现封装原始摘要输出，
    /// 与 [`FieldElement::from_bytes`](crate::ports::FieldElement::from_bytes)
    /// 先例一致；无校验——构造方保证摘要来源合法）。
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 从十六进制字符串解析；`0x` / `0X` 前缀可选接受。
    ///
    /// 解码后必须恰好为 32 字节（64 个 hex 字符），否则返回
    /// [`DomainError::InvalidInput`]。
    pub fn from_hex(s: &str) -> Result<Self, DomainError> {
        let trimmed = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        if trimmed.len() != 64 {
            return Err(DomainError::InvalidInput(format!(
                "hex 长度必须为 64 个字符（32 字节），实际 {} 个",
                trimmed.len()
            )));
        }
        let bytes = hex::decode(trimmed)
            .map_err(|e| DomainError::InvalidInput(format!("非法 hex 字符串：{e}")))?;
        let mut inner = [0u8; 32];
        inner.copy_from_slice(&bytes);
        Ok(Self(inner))
    }

    /// 输出小写 hex 字符串（不带 `0x` 前缀）。
    pub fn as_hex(&self) -> String {
        // hex::encode 固定输出小写
        hex::encode(self.0)
    }

    /// 计算 Keccak-256（与 EVM `keccak256` 一致）。
    pub fn keccak(data: &[u8]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let mut inner = [0u8; 32];
        inner.copy_from_slice(&digest);
        Self(inner)
    }

    /// 是否为全零哈希（哨兵判定）。
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// 以原始 32 字节切片暴露内部值（供承诺前像编码等定长拼接场景）。
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

impl Serialize for Hash32 {
    /// 序列化为 hex 字符串。
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    /// 从 hex 字符串反序列化（接受可选 `0x` 前缀）。
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Hash32::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_known_vector() {
        // Keccak-256("abc") 的公开已知向量
        let h = Hash32::keccak(b"abc");
        assert_eq!(
            h.as_hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn from_hex_roundtrip_with_optional_prefix() {
        let hex_str = "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";
        let h = Hash32::from_hex(hex_str).expect("带 0x 前缀应可解析");

        // 往返：as_hex 输出小写且无前缀，再次 from_hex 得到相同值
        assert_eq!(
            h.as_hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        assert_eq!(Hash32::from_hex(&h.as_hex()).unwrap(), h);
        // 大写输入被归一化为小写输出
        let upper = hex_str.trim_start_matches("0x").to_uppercase();
        assert_eq!(Hash32::from_hex(&upper).unwrap(), h);
        // Display 与 as_hex 一致
        assert_eq!(h.to_string(), h.as_hex());
    }

    #[test]
    fn from_hex_rejects_invalid_input() {
        // 非法 hex 字符
        assert!(Hash32::from_hex("zz").is_err());
        // 长度不足/超出（63 与 65 个字符）
        let short = "ab".repeat(31) + "a";
        let long = format!("{}ff", "ab".repeat(32));
        let e1 = Hash32::from_hex(&short).expect_err("长度不足应报错");
        let e2 = Hash32::from_hex(&long).expect_err("超长应报错");
        assert!(matches!(e1, DomainError::InvalidInput(_)));
        assert!(matches!(e2, DomainError::InvalidInput(_)));
        // 空串
        assert!(Hash32::from_hex("").is_err());
    }

    #[test]
    fn zero_sentinel_semantics() {
        assert!(Hash32::ZERO.is_zero());
        assert!(!Hash32::keccak(b"nonzero").is_zero());
        let all_zero = format!("0x{}", "00".repeat(32));
        assert!(Hash32::from_hex(&all_zero).unwrap().is_zero());
        assert!(!Hash32::ZERO.as_hex().contains('1'));
    }

    #[test]
    fn as_bytes_exposes_raw_digest() {
        let h = Hash32::keccak(b"abc");
        assert_eq!(h.as_bytes().len(), 32);
        assert_eq!(Hash32::keccak(h.as_bytes()), Hash32::keccak(h.as_bytes()));
        assert_eq!(Hash32::ZERO.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn serde_serializes_as_hex_string() {
        let h = Hash32::keccak(b"abc");
        let json = serde_json::to_string(&h).expect("序列化应成功");
        assert_eq!(
            json,
            "\"4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45\""
        );

        let back: Hash32 = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(back, h);

        // 带 0x 前缀的 JSON 输入同样可接受
        let with_prefix = format!("\"0x{}\"", h.as_hex());
        let back2: Hash32 = serde_json::from_str(&with_prefix).expect("0x 前缀应可接受");
        assert_eq!(back2, h);
    }
}
