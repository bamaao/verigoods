//! secp256k1 密钥对与可恢复签名（VG-SIG 中间件与服务端签发复用）。
//!
//! ## 签名口径（写死）
//!
//! - 消息先做 `keccak256(msg)` 预哈希（EVM 风格），再做 ECDSA 可恢复签名；
//! - 签名返回**分离式** `(Signature, RecoveryId)`；
//! - 验签 / 公钥恢复同样以 keccak256 预哈希为 z。
//!
//! ## 公钥摘要与 DID 口径
//!
//! 全仓唯一公钥摘要口径：`keccak256(33 字节压缩 sec1)`（与
//! `vg_domain::identity::VerificationMethod` /
//! [`CompressedPoint::pubkey_digest`](vg_domain::privacy::CompressedPoint::pubkey_digest)
//! 完全一致）。[`pubkey_to_did`] 在其上加 `did:vg:` 前缀得到 DID 字符串。

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use vg_domain::privacy::CompressedPoint;
use vg_domain::shared::Hash32;

use crate::CryptoError;

/// secp256k1 密钥对。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    secret: SecretKey,
    public: PublicKey,
}

impl KeyPair {
    /// 随机生成（CSPRNG）。
    pub fn generate() -> Self {
        let secret = SecretKey::random(&mut OsRng);
        let public = secret.public_key();
        Self { secret, public }
    }

    /// 由已有私钥构造（推导公钥）。
    pub fn from_secret(secret: SecretKey) -> Self {
        let public = secret.public_key();
        Self { secret, public }
    }

    /// 私钥引用。
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// 公钥引用。
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// 压缩 sec1（33 字节）公钥。
    pub fn public_compressed(&self) -> CompressedPoint {
        crate::stealth::compress(&self.public)
    }

    /// 公钥摘要：`keccak256(33B 压缩 sec1)`——全仓唯一口径
    /// （与 domain `VerificationMethod::pubkey_digest` 一致）。
    pub fn pubkey_digest(&self) -> Hash32 {
        self.public_compressed().pubkey_digest()
    }

    /// keccak256 预哈希可恢复签名：`(sig, recovery_id)`。
    pub fn sign_recoverable(&self, msg: &[u8]) -> Result<(Signature, RecoveryId), CryptoError> {
        let prehash = crate::keccak256(msg);
        SigningKey::from(&self.secret)
            .sign_prehash_recoverable(&prehash)
            .map_err(|e| CryptoError::Signing(format!("签名失败：{e}")))
    }
}

/// 验签：`verify(keccak256(msg), sig)`。
pub fn verify(pubkey: &PublicKey, sig: &Signature, msg: &[u8]) -> bool {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let prehash = crate::keccak256(msg);
    VerifyingKey::from(pubkey)
        .verify_prehash(&prehash, sig)
        .is_ok()
}

/// 从签名恢复公钥：`recover(sig, rid, keccak256(msg))`。
pub fn recover(
    sig: &Signature,
    rid: RecoveryId,
    msg: &[u8],
) -> Result<PublicKey, CryptoError> {
    let prehash = crate::keccak256(msg);
    VerifyingKey::recover_from_prehash(&prehash, sig, rid)
        .map(Into::into)
        .map_err(|e| CryptoError::Signing(format!("公钥恢复失败：{e}")))
}

/// 公钥 → `did:vg:<digest hex>` 便捷函数。
///
/// digest = `keccak256(33B 压缩 sec1)`（identity 模块唯一口径，
/// 见 `vg_domain::identity`；VG-SIG 中间件经 recovered pubkey → 本函数得 DID）。
pub fn pubkey_to_did(pubkey: &PublicKey) -> String {
    let digest = crate::stealth::compress(pubkey).pubkey_digest();
    format!("did:vg:{digest}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_unique_and_secret_public_match() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        assert_ne!(a.secret().to_bytes(), b.secret().to_bytes());
        // 公钥与私钥匹配（用标准 verify 验证一条 keccak 预哈希签名链路）
        let (sig, rid) = a.sign_recoverable(b"vg").unwrap();
        assert!(verify(a.public(), &sig, b"vg"));
        let recovered = recover(&sig, rid, b"vg").unwrap();
        assert_eq!(recovered, *a.public());
    }

    #[test]
    fn from_secret_matches_generate_paths() {
        let sk = SecretKey::random(&mut OsRng);
        let kp = KeyPair::from_secret(sk.clone());
        assert_eq!(kp.secret(), &sk);
        assert_eq!(*kp.public(), sk.public_key());
        assert_eq!(kp.public_compressed(), KeyPair::from_secret(sk).public_compressed());
    }

    #[test]
    fn pubkey_digest_is_keccak_of_compressed_33b() {
        let kp = KeyPair::generate();
        let raw = *kp.public_compressed().as_bytes();
        assert_eq!(kp.pubkey_digest(), Hash32::keccak(&raw));
    }

    #[test]
    fn sign_verify_recover_and_tamper_reject() {
        let kp = KeyPair::generate();
        let msg = b"transfer intent payload";
        let (sig, rid) = kp.sign_recoverable(msg).unwrap();

        assert!(verify(kp.public(), &sig, msg));
        // keccak 预哈希口径：等价于 hazmat PrehashVerifier 消费同一 keccak(msg)
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let vk = VerifyingKey::from(kp.public());
        assert!(vk.verify_prehash(&crate::keccak256(msg), &sig).is_ok());

        // 篡改消息
        assert!(!verify(kp.public(), &sig, b"other message"));
        // 篡改签名（翻转 r 的一个字节）
        let mut broken_bytes = sig.to_bytes();
        broken_bytes[3] ^= 0x01;
        let broken: Signature = Signature::try_from(&broken_bytes[..]).unwrap();
        assert!(!verify(kp.public(), &broken, msg));
        // 恢复公钥与原公钥一致
        assert_eq!(recover(&sig, rid, msg).unwrap(), *kp.public());
    }

    #[test]
    fn pubkey_to_did_format() {
        let kp = KeyPair::generate();
        let did = pubkey_to_did(kp.public());
        assert!(did.starts_with("did:vg:"));
        assert_eq!(did.len(), "did:vg:".len() + 64);
        assert_eq!(
            &did["did:vg:".len()..],
            &kp.pubkey_digest().as_hex()
        );
        // 恢复出的公钥得到同一 DID（VG-SIG 链路）
        let (sig, rid) = kp.sign_recoverable(b"auth").unwrap();
        let recovered = recover(&sig, rid, b"auth").unwrap();
        assert_eq!(pubkey_to_did(&recovered), did);
    }
}
