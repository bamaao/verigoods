//! ECIES：ECDH(k256) → HKDF-SHA256 → AES-256-GCM。
//!
//! 供监管 ExtraData（`vg_domain::privacy::EncryptedExtraData`）加密
//! {fromDID, toDID, assetId, ts} 等载荷：发送方用监管 ViewKey 公钥加密，
//! 持有对应私钥方可解密。
//!
//! ## 密文格式（写死）
//!
//! ```text
//! ephemeral 压缩 33B ‖ nonce 12B ‖ AES-256-GCM(ct ‖ 16B tag)
//! ```
//!
//! ## 密钥派生（写死）
//!
//! - ECDH 共享点 x 坐标（32 字节**大端**，k256 `FieldBytes` 原生序）为 ikm；
//! - `HKDF-SHA256(salt = b"vg-ecies-v1", ikm, info = b"vg-ecies-key")`
//!   派生 32 字节 AES-256-GCM 密钥；
//! - nonce 为每次加密的 12 字节随机；
//! - GCM 的 AAD = ephemeral 的 33 字节压缩编码（绑定密文首段：x-only ECDH
//!   下翻转压缩前缀不改变共享 x，必须以 AAD 保证该字节被认证）。

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use k256::elliptic_curve::{bigint::U256, ops::Reduce, point::AffineCoordinates, sec1::ToEncodedPoint};
use k256::{FieldBytes, ProjectivePoint, PublicKey, Scalar, SecretKey};
use rand::RngCore;
use sha2::Sha256;

use crate::CryptoError;

/// HKDF 盐（域分隔，写死）。
const HKDF_SALT: &[u8] = b"vg-ecies-v1";
/// HKDF info（密钥用途分隔，写死）。
const HKDF_INFO: &[u8] = b"vg-ecies-key";
/// GCM nonce 长度（字节，写死）。
const NONCE_LEN: usize = 12;
/// 临时公钥压缩长度。
const EPHEMERAL_LEN: usize = 33;

/// 用对端公钥加密（随机 ephemeral k）。
pub fn encrypt_to(peer: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // 随机 ephemeral 密钥与 nonce
    let mut k_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k_bytes);
    let ephemeral = SecretKey::from_bytes(&FieldBytes::from(k_bytes)).map_err(|e| {
        CryptoError::Signing(format!("ephemeral 私钥生成失败：{e}"))
    })?;
    let ephemeral_pub = ephemeral.public_key();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    // ECDH x 坐标（32B 大端）→ HKDF → AES-256 key
    let shared = ecdh_x(&secret_to_scalar(&ephemeral), peer);
    let key = derive_key(&shared);

    let eph_bytes = ephemeral_pub.to_encoded_point(true);
    let aad = eph_bytes.as_bytes();

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| CryptoError::Signing("AES 密钥长度错误".into()))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptoError::Signing(format!("加密失败：{e}")))?;

    // ephemeral 压缩 33B ‖ nonce 12B ‖ ct‖tag
    let mut out = Vec::with_capacity(EPHEMERAL_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(aad);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 用本方私钥解密 [`encrypt_to`](self::encrypt_to) 的输出。
pub fn decrypt_with(privkey: &SecretKey, bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if bytes.len() < EPHEMERAL_LEN + NONCE_LEN {
        return Err(CryptoError::InvalidCiphertext);
    }
    let (eph, rest) = bytes.split_at(EPHEMERAL_LEN);
    let (nonce_bytes, ct) = rest.split_at(NONCE_LEN);
    let ephemeral_pub =
        PublicKey::from_sec1_bytes(eph).map_err(|_| CryptoError::InvalidCiphertext)?;

    let shared = ecdh_x(&secret_to_scalar(privkey), &ephemeral_pub);
    let key = derive_key(&shared);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| CryptoError::Signing("AES 密钥长度错误".into()))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload { msg: ct, aad: eph },
        )
        .map_err(|_| CryptoError::Decryption)
}

/// ECDH 标量乘取 x 坐标（32 字节大端）。
fn ecdh_x(scalar: &Scalar, peer: &PublicKey) -> [u8; 32] {
    let pt = (ProjectivePoint::from(*peer) * scalar).to_affine();
    pt.x().into()
}

/// HKDF-SHA256 派生 32 字节 AES 密钥（确定，无随机）。
fn derive_key(shared_x: &[u8; 32]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_x)
        .expand(HKDF_INFO, &mut okm)
        .expect("HKDF 输出长度 32B 合法");
    okm
}

/// SecretKey → Scalar（规范序幂等归约）。
fn secret_to_scalar(sk: &SecretKey) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&sk.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (SecretKey, PublicKey) {
        let sk = SecretKey::random(&mut rand::rngs::OsRng);
        (sk.clone(), sk.public_key())
    }

    #[test]
    fn roundtrip_various_lengths() {
        let (sk, pk) = keypair();
        for msg in [
            &b""[..],
            b"a",
            b"hello verigoods",
            &[0u8; 64][..],
            &[0xABu8; 1024][..],
        ] {
            let ct = encrypt_to(&pk, msg).expect("加密应成功");
            let pt = decrypt_with(&sk, &ct).expect("解密应成功");
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn ciphertext_is_randomized_per_encryption() {
        let (_, pk) = keypair();
        let a = encrypt_to(&pk, b"same").unwrap();
        let b = encrypt_to(&pk, b"same").unwrap();
        assert_ne!(a, b, "随机 ephemeral/nonce 应使每次密文不同");
    }

    #[test]
    fn tampering_any_byte_fails() {
        let (sk, pk) = keypair();
        let mut ct = encrypt_to(&pk, b"payload").unwrap();
        for i in 0..ct.len() {
            let mut broken = ct.clone();
            broken[i] ^= 0x01;
            assert!(
                decrypt_with(&sk, &broken).is_err(),
                "篡改第 {i} 字节必须解密失败"
            );
        }
        let _ = &mut ct;
    }

    #[test]
    fn truncation_fails() {
        let (sk, pk) = keypair();
        let ct = encrypt_to(&pk, b"payload").unwrap();
        for len in 0..ct.len() {
            assert!(
                decrypt_with(&sk, &ct[..len]).is_err(),
                "截断至 {len} 字节必须失败"
            );
        }
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, pk) = keypair();
        let (other_sk, _) = keypair();
        let ct = encrypt_to(&pk, b"secret").unwrap();
        assert!(decrypt_with(&other_sk, &ct).is_err());
        assert!(decrypt_with(&sk, &ct).is_ok());
    }

    #[test]
    fn tampered_ephemeral_always_fails() {
        let (sk, pk) = keypair();
        let mut ct = encrypt_to(&pk, b"x").unwrap();
        // 破坏 ephemeral 公钥的 x：若翻转后非曲线上点 → InvalidCiphertext；
        // 若恰为合法点 → 共享秘密改变 → Decryption。两种情形都必须失败
        //（何者出现取决于随机 x，约各半，故只断言 Err）。
        ct[5] ^= 0xFF;
        assert!(decrypt_with(&sk, &ct).is_err());
    }

    #[test]
    fn malformed_ciphertext_shape_rejected() {
        let (sk, _pk) = keypair();
        // 过短（不足 33 + 12）
        assert!(matches!(
            decrypt_with(&sk, &[0u8; 40]),
            Err(CryptoError::InvalidCiphertext)
        ));
        // 首字节非 02/03 压缩前缀 → 非法点
        let mut b = vec![0u8; 45];
        b[0] = 0x04;
        assert!(matches!(
            decrypt_with(&sk, &b),
            Err(CryptoError::InvalidCiphertext)
        ));
    }
}
