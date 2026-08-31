//! 隐匿地址（Stealth Address）派生与扫描（k256 实点运算）。
//!
//! 对应设计文档 §5 模式一：接收方公布
//! [`StealthMetaAddress`](vg_domain::privacy::StealthMetaAddress)
//! （view/spend 一对公钥）；发送方以随机 r 派生一次性地址；接收方用
//! view 私钥扫描识别、用 spend 私钥解锁支出。
//!
//! ## 算法（写死）
//!
//! - 派生（发送方）：`R = r·G`；`sS = r·viewPub`；`t = keccak256(sS.x)`；
//!   `stealth = spendPub + t·G`；一次性地址为
//!   `{ addr_point = 压缩(stealth), ephemeral = 压缩(R) }`。
//! - 扫描（接收方）：`sS' = viewPriv·R`；`t' = keccak256(sS'.x)`；
//!   `P = spendPub + t'·G`；`压缩(P) == addr_point` 即命中。
//!   ECDH 共享点的 x 坐标取 **32 字节大端**（k256 `FieldBytes` 原生序）。
//! - 解锁（支出方）：`d = spendPriv + t (mod n)`，则 `d·G == P`。

use k256::elliptic_curve::{bigint::U256, ops::Reduce, point::AffineCoordinates, sec1::ToEncodedPoint};
use k256::{FieldBytes, ProjectivePoint, PublicKey, Scalar, SecretKey};
use rand::rngs::OsRng;
use vg_domain::privacy::{CompressedPoint, OneTimeAddress, StealthMetaAddress};

use crate::CryptoError;

/// ECDH 共享秘密的原始 x 坐标（32 字节大端）。
///
/// 仅供调用方做进一步 KDF 时使用；隐匿地址算法本身只消费其 keccak。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedSecretBytes(pub [u8; 32]);

/// 扫描命中的解锁信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnlockInfo {
    /// `keccak256(sS.x)`（派生屏蔽因子 t，32 字节）。
    pub t: [u8; 32],
    /// 一次性地址对应的实公钥点 P（支出验证用）。
    pub ot_pub: PublicKey,
}

/// [`StealthMetaAddress`] 的 k256 实点视图（view/spend 公钥均已解压校验）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StealthMetaAddressView {
    /// 扫描用 view 公钥。
    pub view_pub: PublicKey,
    /// 支出用 spend 公钥。
    pub spend_pub: PublicKey,
}

impl TryFrom<&StealthMetaAddress> for StealthMetaAddressView {
    type Error = CryptoError;
    /// 压缩点 → k256 公钥（解压并校验在曲线上；坏点 → [`CryptoError::InvalidPoint`]）。
    fn try_from(meta: &StealthMetaAddress) -> Result<Self, Self::Error> {
        Ok(Self {
            view_pub: decompress(&meta.view_pub)?,
            spend_pub: decompress(&meta.spend_pub)?,
        })
    }
}

impl StealthMetaAddressView {
    /// 由实公钥构造 domain 元地址（反向转换）。
    pub fn from_keys(view_pub: &PublicKey, spend_pub: &PublicKey) -> StealthMetaAddress {
        StealthMetaAddress {
            view_pub: compress(view_pub),
            spend_pub: compress(spend_pub),
        }
    }
}

/// 压缩点 → k256 公钥（`from_sec1_bytes` 做曲线成员校验）。
pub fn decompress(point: &CompressedPoint) -> Result<PublicKey, CryptoError> {
    PublicKey::from_sec1_bytes(point.as_bytes()).map_err(|_| CryptoError::InvalidPoint)
}

/// k256 公钥 → 压缩点（33 字节 sec1，02/03 前缀必然合法）。
pub fn compress(pubkey: &PublicKey) -> CompressedPoint {
    let mut raw = [0u8; 33];
    raw.copy_from_slice(pubkey.to_encoded_point(true).as_bytes());
    CompressedPoint::new(raw).expect("压缩 sec1 编码必然合法")
}

/// 随机派生一次性地址（[`derive_one_time_with_r`] 的随机 r 封装）。
pub fn derive_one_time(
    meta: &StealthMetaAddressView,
) -> (OneTimeAddress, SharedSecretBytes) {
    let r = Scalar::generate_biased(&mut OsRng);
    derive_one_time_with_r(&r, meta)
}

/// 以给定 r 确定性派生一次性地址（测试主路径）。
///
/// 算法：`R = r·G`；`sS = r·viewPub`；`t = keccak256(sS.x)`；
/// `stealth = spendPub + t·G`。返回一次性地址与 sS.x 原始 32 字节。
pub fn derive_one_time_with_r(
    r: &Scalar,
    meta: &StealthMetaAddressView,
) -> (OneTimeAddress, SharedSecretBytes) {
    let g = ProjectivePoint::GENERATOR;
    let r_pt = g * r;
    let ss = ProjectivePoint::from(meta.view_pub) * r;
    let x = ss.to_affine().x(); // 32 字节大端

    let t = crate::keccak256(x.as_slice());
    let t_scalar = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(t));
    let stealth = ProjectivePoint::from(meta.spend_pub) + g * t_scalar;

    (
        OneTimeAddress {
            addr_point: compress(&PublicKey::from_affine(stealth.to_affine()).expect("合法点")),
            ephemeral: compress(&PublicKey::from_affine(r_pt.to_affine()).expect("合法点")),
        },
        SharedSecretBytes(x.into()),
    )
}

/// 接收方扫描：命中返回 [`UnlockInfo`]，否则 `None`。
///
/// `sS' = viewPriv·R`；`t' = keccak256(sS'.x)`；`P = spendPub + t'·G`；
/// `压缩(P) == ot.addr_point` 即命中。
pub fn scan_and_unlock(
    view_priv: &SecretKey,
    ot: &OneTimeAddress,
    spend_pub: &PublicKey,
) -> Option<UnlockInfo> {
    let g = ProjectivePoint::GENERATOR;
    let r_pt = ProjectivePoint::from(decompress(&ot.ephemeral).ok()?);
    let ss = r_pt * secret_to_scalar(view_priv);
    let x = ss.to_affine().x();

    let t = crate::keccak256(x.as_slice());
    let t_scalar = <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(t));
    let p = ProjectivePoint::from(spend_pub) + g * t_scalar;
    let p_pub = PublicKey::from_affine(p.to_affine()).ok()?;

    if compress(&p_pub) == ot.addr_point {
        Some(UnlockInfo { t, ot_pub: p_pub })
    } else {
        None
    }
}

/// 解锁支出私钥：`d = spendPriv + t (mod n)`（满足 `d·G == P`，测试断言）。
pub fn unlock_spend_key(spend_priv: &SecretKey, info: &UnlockInfo) -> SecretKey {
    let d = secret_to_scalar(spend_priv)
        + <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(info.t));
    SecretKey::from_bytes(&d.to_bytes()).expect("d 非零且 < n（溢出概率可忽略）")
}

/// SecretKey → Scalar（`to_bytes` 为规范序，`reduce_bytes` 幂等归约）。
fn secret_to_scalar(sk: &SecretKey) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&sk.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (SecretKey, PublicKey) {
        let sk = SecretKey::random(&mut OsRng);
        let pk = sk.public_key();
        (sk, pk)
    }

    fn meta_fixture() -> (SecretKey, PublicKey, SecretKey, PublicKey, StealthMetaAddressView) {
        let (view_sk, view_pk) = keypair();
        let (spend_sk, spend_pk) = keypair();
        let meta = StealthMetaAddressView {
            view_pub: view_pk,
            spend_pub: spend_pk,
        };
        (view_sk, view_pk, spend_sk, spend_pk, meta)
    }

    #[test]
    fn compress_decompress_roundtrip_and_bad_point_rejected() {
        let (_, pk) = keypair();
        let cp = compress(&pk);
        assert_eq!(decompress(&cp).unwrap(), pk);
        // 坏点：前缀合法但 x 不在曲线上 → 拒绝（单个 x 翻转后可能仍是
        // 曲线上的合法点，故扫描多个确定性变形，至少一个必须被拒绝——
        // 全部通过的概率为 2^-n，可视为不可能事件）
        let mut rejected = false;
        for i in 0..20 {
            let mut raw = *cp.as_bytes();
            raw[5 + i] ^= 0xFF;
            if matches!(
                decompress(&CompressedPoint::new(raw).unwrap()),
                Err(CryptoError::InvalidPoint)
            ) {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "确定性变形中应存在非曲线点被拒绝");
    }

    #[test]
    fn meta_view_try_from_and_back() {
        let (_, view_pk) = keypair();
        let (_, spend_pk) = keypair();
        let domain = StealthMetaAddressView::from_keys(&view_pk, &spend_pk);
        let back: StealthMetaAddressView = (&domain).try_into().unwrap();
        assert_eq!(back.view_pub, view_pk);
        assert_eq!(back.spend_pub, spend_pk);
    }

    #[test]
    fn derive_and_scan_end_to_end_consistency() {
        let (view_sk, _, spend_sk, spend_pk, meta) = meta_fixture();
        let r = Scalar::generate_biased(&mut OsRng);
        let (ot, shared) = derive_one_time_with_r(&r, &meta);

        // 确定性：同 r 同输出
        let (ot2, shared2) = derive_one_time_with_r(&r, &meta);
        assert_eq!(ot, ot2);
        assert_eq!(shared, shared2);

        // 接收方扫描命中
        let info = scan_and_unlock(&view_sk, &ot, &spend_pk).expect("应当命中");
        // t = keccak(sS.x) 与发送侧一致（shared 即 sS.x）
        assert_eq!(info.t, crate::keccak256(&shared.0));

        // 解锁私钥满足 d·G == P
        let d = unlock_spend_key(&spend_sk, &info);
        let p = ProjectivePoint::GENERATOR * secret_to_scalar(&d);
        assert_eq!(PublicKey::from_affine(p.to_affine()).unwrap(), info.ot_pub);
        // 且 d·G 的压缩编码 == 一次性地址点
        assert_eq!(compress(&info.ot_pub), ot.addr_point);
    }

    #[test]
    fn scan_miss_returns_none() {
        // 正确 view 密钥但错误的 spend 公钥 → 不命中
        let (view_sk, _, _, spend_pk, meta) = meta_fixture();
        let r = Scalar::generate_biased(&mut OsRng);
        let (ot, _) = derive_one_time_with_r(&r, &meta);
        // 用别人的 spend 公钥扫描
        let (_, wrong_spend) = keypair();
        let _ = spend_pk;
        assert!(scan_and_unlock(&view_sk, &ot, &wrong_spend).is_none());

        // 错误的 view 私钥 → 不命中
        let (wrong_view, _, _, _, _) = meta_fixture();
        assert!(scan_and_unlock(&wrong_view, &ot, &spend_pk).is_none());
    }

    #[test]
    fn random_derive_differs_each_time() {
        let (_, _, _, _, meta) = meta_fixture();
        let (a, _) = derive_one_time(&meta);
        let (b, _) = derive_one_time(&meta);
        assert_ne!(a, b, "随机 r 必须产生不同一次性地址");
    }
}
