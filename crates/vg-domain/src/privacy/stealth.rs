//! 隐形地址（Stealth Address）原语。
//!
//! VeriGoods 的双隐私模式（Shielded Transactions + Private Validium）都依赖
//! 隐形地址机制隐藏收款方：发送方用接收方公布的 [`StealthMetaAddress`]
//! （view/spend 一对公钥）派生一次性的 [`OneTimeAddress`]，仅持有 view 私钥的
//! 一方可扫描识别、仅持有 spend 私钥的一方日后可支出。
//!
//! 领域层只承载**压缩点数据与其摘要口径**；实际的 ECDH 派生与扫描运算
//! （k256 实点运算）属于基础设施层（vg-infra-crypto，Task 10 实现，
//! 依赖方向 infra → domain）。

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::shared::{DomainError, Hash32};

/// SEC1 压缩椭圆曲线公钥点（33 字节）。
///
/// 首字节必须为 `0x02` / `0x03`（偶/奇 y 坐标前缀），其余 32 字节为 x 坐标。
/// serde 序列化为 66 个 hex 字符的字符串（不带 `0x`）；
/// 反序列化为手写实现并强制走 [`CompressedPoint::from_hex`] 校验前缀
/// （与 [`Did`](crate::shared::Did) 的先例一致）。
///
/// 注意：点是否真正落在曲线上由 infra 侧（k256）在实点运算时校验，
/// 领域层只锁死编码合法性（长度 + 前缀）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompressedPoint([u8; 33]);

impl CompressedPoint {
    /// 合法压缩前缀：偶 y（0x02）与奇 y（0x03）。
    const PREFIXES: [u8; 2] = [0x02, 0x03];

    /// 从原始 33 字节构造；首字节必须为 `0x02`/`0x03`。
    pub fn new(bytes: [u8; 33]) -> Result<Self, DomainError> {
        if !Self::PREFIXES.contains(&bytes[0]) {
            return Err(DomainError::InvalidInput(format!(
                "压缩点前缀必须为 0x02 或 0x03，实际 0x{:02x}",
                bytes[0]
            )));
        }
        Ok(Self(bytes))
    }

    /// 从十六进制字符串解析；恰好 66 个 hex 字符（33 字节），
    /// `0x`/`0X` 前缀可选接受，随后委托 [`CompressedPoint::new`] 校验前缀。
    pub fn from_hex(s: &str) -> Result<Self, DomainError> {
        let trimmed = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        if trimmed.len() != 66 {
            return Err(DomainError::InvalidInput(format!(
                "压缩点 hex 长度必须为 66 个字符（33 字节），实际 {} 个",
                trimmed.len()
            )));
        }
        let bytes = hex::decode(trimmed)
            .map_err(|e| DomainError::InvalidInput(format!("非法 hex 字符串：{e}")))?;
        let mut inner = [0u8; 33];
        inner.copy_from_slice(&bytes);
        Self::new(inner)
    }

    /// 输出小写 hex 字符串（不带 `0x` 前缀）。
    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// 以原始 33 字节暴露（供 infra 侧实点运算）。
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    /// 公钥摘要：`keccak256(33 字节压缩 sec1)`。
    ///
    /// 这是全仓唯一的公钥摘要口径，与
    /// [`identity::VerificationMethod`](crate::identity::VerificationMethod)
    /// 的 `pubkey_digest` 完全一致（见 identity 模块约定）。
    pub fn pubkey_digest(&self) -> Hash32 {
        Hash32::keccak(&self.0)
    }
}

impl Serialize for CompressedPoint {
    /// 序列化为 hex 字符串（与 [`Hash32`](crate::shared::Hash32) 风格一致）。
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for CompressedPoint {
    /// 从 hex 字符串反序列化；强制经过 [`CompressedPoint::from_hex`]
    /// 的前缀校验，非法输入映射为 serde 数据错误。
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        CompressedPoint::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// 隐形地址元地址：接收方公布的一对公钥（扫描用 view 公钥 + 支出用 spend 公钥）。
///
/// 说明：plan 草图曾写为 `Hash32`，但把 33 字节压缩点截进 32 字节哈希会
/// 丢失扫描所需的实点信息——Task 10 的 ECDH 派生与扫描必须用实点运算，
/// 因此此处保留 [`CompressedPoint`]（授权修正）；
/// 需要摘要时用 [`CompressedPoint::pubkey_digest`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StealthMetaAddress {
    /// view 公钥（扫描方持有对应私钥即可识别属于自己的付款）。
    pub view_pub: CompressedPoint,
    /// spend 公钥（持有对应私钥方可支出该隐形地址上的资产）。
    pub spend_pub: CompressedPoint,
}

/// 一次性隐形地址：发送方为单笔付款派生的收款地址。
///
/// `ephemeral` 为随机数 r 对应的公钥点 `R = rG`，随付款公布，
/// 供接收方用 view 私钥做 ECDH 扫描（派生/扫描算法在 infra，Task 10）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OneTimeAddress {
    /// 收款地址点（P = H(r·V)G + S 形式派生的公钥）。
    pub addr_point: CompressedPoint,
    /// 临时公钥 `R = rG`，公布用于扫描。
    pub ephemeral: CompressedPoint,
}

impl OneTimeAddress {
    /// 地址摘要：`keccak256(addr_point 的 33 字节压缩编码)`。
    ///
    /// [`Note`](super::note::Note) 的 `owner_ot_addr` 字段即引用该摘要
    /// （32 字节定长，便于承诺编码与链上 bytes32 表达）。
    pub fn addr_digest(&self) -> Hash32 {
        self.addr_point.pubkey_digest()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造合法压缩点（前缀 0x02 + 递增 x）。
    fn point(prefix: u8) -> [u8; 33] {
        let mut b = [0u8; 33];
        b[0] = prefix;
        for (i, v) in b.iter_mut().enumerate().skip(1) {
            *v = (i as u8).wrapping_mul(7);
        }
        b
    }

    #[test]
    fn new_accepts_valid_prefixes_only() {
        assert!(CompressedPoint::new(point(0x02)).is_ok());
        assert!(CompressedPoint::new(point(0x03)).is_ok());
        for bad in [0x00u8, 0x01, 0x04, 0xFF] {
            let err = CompressedPoint::new(point(bad)).expect_err("非法前缀应被拒绝");
            assert!(
                matches!(err, DomainError::InvalidInput(_)),
                "前缀 0x{bad:02x} 实际错误：{err:?}"
            );
        }
    }

    #[test]
    fn hex_roundtrip() {
        for prefix in [0x02u8, 0x03] {
            let p = CompressedPoint::new(point(prefix)).unwrap();
            let hex = p.as_hex();
            assert_eq!(hex.len(), 66);
            assert!(hex.starts_with(match prefix {
                0x02 => "02",
                _ => "03",
            }));
            let back = CompressedPoint::from_hex(&hex).unwrap();
            assert_eq!(back, p);
            // 0x 前缀可选接受
            let with_prefix = format!("0x{hex}");
            assert_eq!(CompressedPoint::from_hex(&with_prefix).unwrap(), p);
        }
    }

    #[test]
    fn from_hex_rejects_bad_input() {
        // 长度错误
        assert!(CompressedPoint::from_hex("02ab").is_err());
        assert!(CompressedPoint::from_hex("").is_err());
        assert!(CompressedPoint::from_hex(&"ab".repeat(33)).is_err());
        // 非法 hex 字符（长度正确）
        let mut bad = "0z".to_string();
        bad.push_str(&"ab".repeat(32));
        assert!(CompressedPoint::from_hex(&bad).is_err());
        // 长度正确但前缀非法（00 / 04 / 乱码开头）
        for prefix in ["00", "04", "zz"] {
            let mut s = prefix.to_string();
            s.push_str(&"ab".repeat(32));
            let err = CompressedPoint::from_hex(&s).expect_err("非法前缀应被拒绝");
            assert!(
                matches!(err, DomainError::InvalidInput(_)),
                "前缀 {prefix} 实际错误：{err:?}"
            );
        }
    }

    #[test]
    fn serde_roundtrip_and_rejects_invalid() {
        let p = CompressedPoint::new(point(0x03)).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, format!("\"{}\"", p.as_hex()));
        let back: CompressedPoint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);

        // 反序列化同样强制前缀校验（手写 Deserialize 委托构造函数）
        let mut bad = String::from("\"04");
        bad.push_str(&"ab".repeat(32));
        bad.push('"');
        let err =
            serde_json::from_str::<CompressedPoint>(&bad).expect_err("非法前缀反序列化必须失败");
        assert!(err.is_data(), "应为数据错误：{err}");
        // 坏 hex / 长度错误同样拒绝
        assert!(serde_json::from_str::<CompressedPoint>("\"nothex\"").is_err());
        assert!(serde_json::from_str::<CompressedPoint>("\"02ab\"").is_err());
    }

    #[test]
    fn pubkey_digest_matches_keccak_of_33_bytes() {
        let raw = point(0x02);
        let p = CompressedPoint::new(raw).unwrap();
        // golden：与直接手算 keccak(33B) 一致（与 identity 的唯一口径对齐）
        assert_eq!(p.pubkey_digest(), Hash32::keccak(&raw));
        // 不同点 → 不同摘要
        let mut other = raw;
        other[5] ^= 0xFF;
        assert_ne!(
            CompressedPoint::new(other).unwrap().pubkey_digest(),
            p.pubkey_digest()
        );
    }

    #[test]
    fn meta_and_one_time_address_serde_roundtrip() {
        let meta = StealthMetaAddress {
            view_pub: CompressedPoint::new(point(0x02)).unwrap(),
            spend_pub: CompressedPoint::new(point(0x03)).unwrap(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: StealthMetaAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(back, meta);

        let ota = OneTimeAddress {
            addr_point: CompressedPoint::new(point(0x02)).unwrap(),
            ephemeral: CompressedPoint::new(point(0x03)).unwrap(),
        };
        let json = serde_json::to_string(&ota).unwrap();
        let back: OneTimeAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ota);

        // addr_digest == keccak(addr_point)
        assert_eq!(ota.addr_digest(), ota.addr_point.pubkey_digest());
    }
}
