//! Poseidon2（KoalaBear）host 端 Note 承诺哈希。
//!
//! 实现 [`vg_domain::ports::NoteHasher`] 端口，与 Task 11 的 note_opening
//! 电路**按同一 sponge 规范复算**——本模块文档即为电路侧对齐的唯一依据，
//! 任何改动必须同步电路与两侧 golden vector。
//!
//! ## Sponge 规范（逐步，写死无随机）
//!
//! **置换**：`p3_koala_bear::default_koalabear_poseidon2_16()`，即
//! Poseidon2 over KoalaBear（p = 2^31 − 2^24 + 1）：
//! - 状态宽度 `WIDTH = 16`，S-box 幂次 `d = 3`（`KOALABEAR_S_BOX_DEGREE`）；
//! - 外部全轮 `R_F = 8`（4 初始 + 4 终末），内部部分轮 `R_P = 20`；
//! - 轮常数由 Grain LFSR 生成（参数 field=1, alpha=3, n=31, t=16,
//!   R_F=8, R_P=20，见 p3-koala-bear 0.7.0-rc.1 源码注释）；
//! - 外部层线性矩阵为 M4 复合轻量 MDS，内部层扩散矩阵 `1 + Diag(V)`，
//!   V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24,
//!   -1/2^8, -1/8, -1/16, -1/2^24]。
//!
//! **32 字节词 → 域元素**（与
//! [`Note::commitment_parts`](vg_domain::privacy::Note::commitment_parts)
//! 的编码规范配套）：词 b[0..32] 拆 8 个连续小端 u32 limb
//! （`u32_le(b[0..4])` .. `u32_le(b[28..32])`），每个 limb 经
//! `KoalaBear::from_int(limb)` 规范归约载入（见 [`to_field_le`]）。
//!
//! **哈希流程**（RATE = 8，CAPACITY = 8）：
//! 1. 域分隔初始化：`L = keccak256("vg:poseidon:v1")`（32 字节）→
//!    `to_field_le(L)` 得 8 个 limb；状态 `[F; 16]` 置全零后，
//!    `state[0..8] += L`（域加法），置换一次；
//! 2. 输入 limbs：parts 各词按序 [`to_field_le`] 后顺序拼接；
//! 3. 填充（域上 10\*1 变体）：在 limbs 末尾追加单个值为 **1**（乘法单位元）
//!    的 limb，再以零 limb 补齐至长度为 8 的倍数（若追加 sentinel 后恰好
//!    对齐则不补零）；
//! 4. 吸收：对每个连续 8-limb 块 b：`state[0..8] += b`，置换一次；
//! 5. 挤压：取最终状态 `state[0..8]` 共 8 个域元素（单次 squeeze），
//!    每个经 `as_canonical_u32()` → 4 字节小端 → 顺序拼接 32 字节，
//!    即为 [`Hash32`](vg_domain::shared::Hash32) 承诺输出。
//!
//! 整个流程纯确定性：同输入必同输出。golden 6 词 fixture（来自 vg-domain
//! `commitment_parts_golden_vector`）的承诺 hex 已写死在本模块测试中，
//! Task 11 电路以此对齐。

use p3_field::integers::QuotientMap;
use p3_field::PrimeField32;
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_symmetric::Permutation;
use vg_domain::ports::NoteHasher;
use vg_domain::shared::Hash32;

/// 状态宽度（写死：p3-koala-bear 预置 Poseidon2 置换宽度）。
const WIDTH: usize = 16;
/// sponge 速率（每块吸收的 limb 数，写死为宽度一半）。
const RATE: usize = 8;
/// squeeze 输出的域元素个数（8 × u32 = 32 字节）。
const SQUEEZE: usize = 8;
/// 域分隔标签（见模块文档第 1 步）。
const DOMAIN_LABEL: &[u8] = b"vg:poseidon:v1";

/// 32 字节词 → 8 个 KoalaBear 域元素。
///
/// 词 b[0..32] 拆 8 个连续小端 u32 limb，每个 limb 经
/// `KoalaBear::from_int(limb)` 规范归约载入（KoalaBear 为 31-bit
/// 素域，u32 limb 可能 ≥ p，from_int 做模 p 归约）。
pub fn to_field_le(bytes: &[u8; 32]) -> Vec<KoalaBear> {
    let mut out = Vec::with_capacity(8);
    for i in 0..8 {
        let limb = u32::from_le_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ]);
        out.push(KoalaBear::from_int(limb));
    }
    out
}

/// 域元素 → 4 字节小端（squeeze 输出编码）。
fn elem_to_le_bytes(e: &KoalaBear) -> [u8; 4] {
    e.as_canonical_u32().to_le_bytes()
}

/// 惰性构造共享置换（轮常数全为编译期预置常量，构造确定性）。
fn permutation() -> Poseidon2KoalaBear<WIDTH> {
    default_koalabear_poseidon2_16()
}

/// 按 [`poseidon`](self) 模块文档的 sponge 规范，对任意长度 32 字节词
/// 序列计算 Poseidon2 承诺。
///
/// 对 parts 长度通用（golden 6 词只是 fixture）；空 parts 走
/// 「仅 sentinel 块」路径，不 panic。
pub fn poseidon_note_commitment(parts: &[[u8; 32]]) -> Hash32 {
    let perm = permutation();

    // 1. 域分隔初始化：吸收 keccak256(DOMAIN_LABEL) 后置换一次
    let label = crate::keccak256(DOMAIN_LABEL);
    let mut state = [KoalaBear::from_int(0u32); WIDTH];
    for (s, l) in state.iter_mut().zip(to_field_le(&label)) {
        *s += l;
    }
    perm.permute_mut(&mut state);

    // 2. 输入 limbs 拼接
    let mut limbs: Vec<KoalaBear> = Vec::with_capacity(parts.len() * 8);
    for word in parts {
        limbs.extend(to_field_le(word));
    }

    // 3. 填充：sentinel 1 + 零补齐至 RATE 倍数
    limbs.push(KoalaBear::from_int(1u32));
    while !limbs.len().is_multiple_of(RATE) {
        limbs.push(KoalaBear::from_int(0u32));
    }

    // 4. 逐块吸收（域加法进 rate 槽后置换）
    for block in limbs.chunks_exact(RATE) {
        for i in 0..RATE {
            state[i] += block[i];
        }
        perm.permute_mut(&mut state);
    }

    // 5. squeeze：state[0..8] → 各 4 字节小端拼 32B
    let mut out = [0u8; 32];
    for i in 0..SQUEEZE {
        out[4 * i..4 * i + 4].copy_from_slice(&elem_to_le_bytes(&state[i]));
    }
    Hash32::from_bytes(out)
}

/// [`NoteHasher`] 端口的 Poseidon2 实现（无状态，可全局共享）。
#[derive(Debug, Clone, Copy, Default)]
pub struct PoseidonNoteHasher;

impl NoteHasher for PoseidonNoteHasher {
    fn note_commitment(&self, parts: &[[u8; 32]]) -> Hash32 {
        poseidon_note_commitment(parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vg_domain::privacy::Note;
    use vg_domain::shared::{BatchId, Hash32 as H, SubjectRef};

    /// 复刻 vg-domain `commitment_parts_golden_vector` 的黄金 Note。
    fn golden_note() -> Note {
        let owner = H::from_hex(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let mut secret = [0u8; 32];
        secret[0] = 0x22;
        let mut salt = [0u8; 16];
        salt[..4].copy_from_slice(&[0x33, 0x44, 0x55, 0x66]);
        Note::new(
            SubjectRef::Batch(BatchId::new("golden-1")),
            owner,
            7,
            secret,
            salt,
        )
        .expect("黄金向量构造应成功")
    }

    /// 黄金 Note 的 6 词前像（与 vg-domain golden vector 逐字一致）。
    fn golden_parts() -> Vec<[u8; 32]> {
        let word = |hex: &str| -> [u8; 32] {
            hex::decode(hex).unwrap().try_into().unwrap()
        };
        vec![
            word("a4c41c2383a5fd0b250bce28a902ebfb3480349f8714a9232a3dd279831f061d"),
            word("0ac2d6796d51fb5318755791b4b3e1e9180d58e74167ea2a71c81b4cbe41be52"),
            word("1111111111111111111111111111111111111111111111111111111111111111"),
            word("0700000000000000000000000000000000000000000000000000000000000000"),
            word("2200000000000000000000000000000000000000000000000000000000000000"),
            word("0000000000000000000000000000000033445566000000000000000000000000"),
        ]
    }

    #[test]
    fn to_field_le_maps_limb_wise() {
        // 全零 → 全零域元素
        assert!(to_field_le(&[0u8; 32]).iter().all(|e| e.as_canonical_u32() == 0));
        // 低 4 字节 = 0x01000000（小端 limb[0] = 1）
        let mut b = [0u8; 32];
        b[0] = 1;
        let f = to_field_le(&b);
        assert_eq!(f[0].as_canonical_u32(), 1);
        assert!(f[1..].iter().all(|e| e.as_canonical_u32() == 0));
        // 归约：limb = 0xFFFFFFFF > p，应归约为 0xFFFFFFFF mod p
        let mut x = [0u8; 32];
        x[..4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        let limb = 0xFFFFFFFFu32;
        let expected = KoalaBear::from_int(limb).as_canonical_u32();
        assert_eq!(to_field_le(&x)[0].as_canonical_u32(), expected);
    }

    #[test]
    fn deterministic_for_same_input() {
        let parts = golden_parts();
        assert_eq!(
            poseidon_note_commitment(&parts),
            poseidon_note_commitment(&parts)
        );
    }

    #[test]
    fn bit_flip_in_any_word_changes_output() {
        let base = poseidon_note_commitment(&golden_parts());
        for w in 0..6 {
            for bit in [1u8, 7, 0x80, 255] {
                let mut parts = golden_parts();
                parts[w][0] ^= bit;
                assert_ne!(
                    poseidon_note_commitment(&parts),
                    base,
                    "词 {w} 翻转字节 {bit} 必须改变承诺"
                );
            }
        }
    }

    #[test]
    fn empty_parts_does_not_panic() {
        let h = poseidon_note_commitment(&[]);
        assert_ne!(h, Hash32::ZERO);
        assert_eq!(h, poseidon_note_commitment(&[]));
    }

    #[test]
    fn golden_note_parts_match_domain_fixture() {
        // 以 vg-domain 黄金 Note 为 fixture：本 crate 消费的前像与领域层一致
        assert_eq!(golden_note().commitment_parts(), golden_parts());
    }

    #[test]
    fn golden_commitment_hex_fixture() {
        // **字面 golden fixture**（Task 11 电路对齐锚点）：
        // poseidon_note_commitment(golden parts) 的 hex 输出写死如下。
        let h = poseidon_note_commitment(&golden_parts());
        assert_eq!(
            h.as_hex(),
            "a161d8663eae644891afc05c9c9b4b42c7100a4d04e5882a48835b4c5e0f857d"
        );
    }

    #[test]
    fn note_commitment_via_hasher_trait() {
        // 端口注入集成：Note::commitment(&PoseidonNoteHasher) 与直接调用一致
        let note = golden_note();
        let via_trait = note.commitment(&PoseidonNoteHasher);
        assert_eq!(via_trait, poseidon_note_commitment(&golden_parts()));
        // 不同 Note（换 salt 位）→ 不同承诺
        let other = Note::new(
            note.asset_ref().clone(),
            note.owner_ot_addr(),
            note.amount(),
            *note.secret(),
            {
                let mut s = *note.salt();
                s[0] ^= 0x01;
                s
            },
        )
        .unwrap();
        assert_ne!(
            other.commitment(&PoseidonNoteHasher),
            via_trait
        );
    }
}
