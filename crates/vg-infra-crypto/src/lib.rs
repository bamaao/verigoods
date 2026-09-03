//! # vg-infra-crypto：VeriGoods 隐私层密码学原语。
//!
//! 本 crate 是基础设施层对 vg-domain 隐私端口的实现载体（依赖方向
//! infra → domain），提供四组同步原语（无 tokio、无 unsafe、无配置化参数，
//! 算法全部写死）：
//!
//! - [`keypair`]：secp256k1 密钥对生成 / keccak256 预哈希可恢复签名 / 验签 /
//!   公钥恢复，以及 `did:vg:` DID 便捷口径（VG-SIG 中间件与服务端签发复用）；
//! - [`stealth`]：隐匿地址（Stealth Address）派生与扫描（k256 实点运算），
//!   对应 domain 的 `StealthMetaAddress` / `OneTimeAddress`；
//! - [`ecies`]：ECIES 加解密（ECDH → HKDF-SHA256 → AES-256-GCM），
//!   供监管 ExtraData（`EncryptedExtraData`）加密使用；
//! - [`poseidon`]：Poseidon2（KoalaBear）host 端 Note 承诺哈希，实现
//!   domain 端口 [`NoteHasher`](vg_domain::ports::NoteHasher)，
//!   与 Task 11 的 note_opening 电路按同一 sponge 规范复算对齐。
//!
//! ## 公钥摘要唯一口径
//!
//! 全仓公钥摘要口径为 `keccak256(33 字节压缩 sec1)`，见
//! `vg_domain::privacy::CompressedPoint::pubkey_digest`；本 crate 的
//! [`keypair::pubkey_to_did`] 等便捷函数严格遵循该口径。

pub mod ecies;
pub mod keypair;
pub mod poseidon;
pub mod stealth;

pub use ecies::{decrypt_with, encrypt_to};
pub use keypair::{pubkey_to_did, KeyPair};
pub use poseidon::{poseidon_note_commitment, to_field_le, PoseidonNoteHasher};
pub use stealth::{
    derive_one_time, derive_one_time_with_r, scan_and_unlock, unlock_spend_key, SharedSecretBytes,
    StealthMetaAddressView, UnlockInfo,
};
/// 领域层 32 字节哈希类型（承诺输出对账口径，供 vg-infra-zk 复用）。
pub use vg_domain::shared::Hash32;

/// 密码学原语统一错误。
///
/// 只做粗粒度分类（infra 层不越权映射 HTTP 状态码；如需区分 400/401
/// 由上层映射层处理）。
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// 非法曲线点（解压/解析 sec1 失败、不在曲线上等）。
    #[error("非法椭圆曲线点")]
    InvalidPoint,
    /// 密文结构非法（长度不足、临时公钥解析失败等）。
    #[error("非法密文")]
    InvalidCiphertext,
    /// 对称解密失败（AEAD 认证校验未通过）。
    #[error("解密失败：密文被篡改或不匹配")]
    Decryption,
    /// 加密路径失败（ephemeral 私钥构造、密钥派生、AEAD 加密）。
    #[error("加密运算失败：{0}")]
    Encryption(String),
    /// 非法标量（ephemeral 标量退化使 ECDH 乘积为无穷远点）。
    #[error("非法标量：ECDH 共享点退化")]
    InvalidScalar,
    /// 签名/恢复/私钥构造失败。
    #[error("签名运算失败：{0}")]
    Signing(String),
}

/// 生成 Note secret（32 字节，OsRng）。
///
/// 应用层不直接接触 RNG——随机性口径统一收敛在 crypto 基础设施。
pub fn generate_note_secret() -> [u8; 32] {
    use rand::RngCore;
    let mut s = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut s);
    s
}

/// 生成 Note salt（16 字节，OsRng）。
pub fn generate_note_salt() -> [u8; 16] {
    use rand::RngCore;
    let mut s = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut s);
    s
}

/// keccak-256（EVM 变体，与 `vg_domain::shared::Hash32::keccak` 一致）。
///
/// pub 化供 vg-infra-zk 复算 Poseidon2 域分隔标签（跨 crate 共用同一
/// 口径，勿在别处重复实现）。
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut h = sha3::Keccak256::new();
    h.update(data);
    h.finalize().into()
}
