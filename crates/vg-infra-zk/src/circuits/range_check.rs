//! range_check 电路：证明「知道 Poseidon2 承诺 C = Commit(x‖salt) 的
//! 前像，且整数 x ≤ B」。
//!
//! ## 语义
//!
//! - **公开输入**（11 个）：`[B_c0, B_c1, B_c2, C_0..C_7]`——B 的三个
//!   30-bit chunk（base 2^30，`B = Σ B_cj·2^{30j}`，每个恒 < 2^30 < p，
//!   canonical 装载无失真，验证方整数重建 B），C 的 8 个 limb（与
//!   note_opening 的 C 编码一致，即 host 侧
//!   [`vg_infra_crypto::poseidon::poseidon_note_commitment`] squeeze
//!   输出的 8 × u32 小端值）；
//! - **私有见证**：x（u64）、salt（16 字节）；
//! - **语句**：x 的 90 位（3 chunk × 30 位）分解精确重建 x ∧ 整数
//!   x ≤ B（逐位比较）∧ C = sponge(词(x), 词(salt))。
//!
//! ## 无环绕原则（本电路 soundness 的基石）
//!
//! KoalaBear 素数 p = 0x7F000001 = 2 131 706 433 > 2^30。**30 个位的
//! 加权和 ≤ 2^30 − 1 < p**，因此「30 位逐位加倍累积 == chunk 域值」的
//! 域等式即整数等式，无 mod-p 环绕——chunk 被其位分解唯一确定，
//! x 与 B 的整数语义由此精确进入约束。若用 64 位/32 位分解，位和可
//! 超 p，域等式退化为 mod-p 同余（本电路前一版本的实际漏洞：承诺
//! x = 2^32、B = 100 时可用 x mod p / 100 + p 形态的位分解通过全部
//! 约束），30-bit chunk 化正是对该漏洞的修复。
//!
//! ## 承诺编码（写死锁定）
//!
//! [`range_commitment_parts`]：
//! - 词 0 = x：**LE 装载 3 个 chunk 的 u32 值**——bytes 0..4 = c0（低
//!   30 bit）、4..8 = c1、8..12 = c2、余零。每个 u32 < 2^30 < p，
//!   `from_int` 恒等装载、无归约歧义（limb ≥ p 时 u32↔域值本就有
//!   2^-7 级歧义，chunk 装载使 x 侧无此歧义）；
//! - 词 1 = salt：低 16 字节零、高 16 字节 = salt（与 Note salt 词
//!   同构，见 `vg_domain::privacy::Note::commitment_parts` 的
//!   `salt_word[16..] = salt`；salt 为自由见证、无比较语义，保留
//!   Note 编码不受无环绕约束影响）；
//! - C = `poseidon_note_commitment(&parts)`（1 label 行置换 + 2 词
//!   16 limb + sentinel 1 + 7 零 → 24 limb = 3 块吸收）。
//!
//! ## AIR 结构（列区间表 + 行布局）
//!
//! 位分解/比较区与置换链区**并行列区、行复用**：trace 高度固定 128
//! 行（2 的幂），每行既是位行 r（行 0..89 承载 90 位整数
//! `v = Σ b_i·2^i` 的第 i = 89−r 位，MSB 在前，即 chunk2 位→chunk1→
//! chunk0），又是一次完整 Poseidon2 置换。总列宽 = 164 + 28 = 192：
//!
//! | 列区间 | 宽度 | 语义 |
//! |---|---|---|
//! | `0..164` | 164 | `Poseidon2Cols<16,3,0,4,20>`：置换链（镜像 p3-poseidon2-air） |
//! | `164..172` | 8 | `block[8]`：吸收块（**内容被约束 6 钉死**，非自由见证——与 note_opening 的关键区别） |
//! | `172` | 1 | `t`：sponge 链布尔标志（0 = 填充行，1 = 真实行；单调 0→1） |
//! | `173..175` | 2 | `c1, c0`：真实行块计数器的两个位（c = 2·c1 + c0） |
//! | `175..177` | 2 | `xb, bb`：本行 x / B 的位 |
//! | `177..180` | 3 | `xa0..xa2`：chunk 累积器（区 j = 行 30j..30j+29，加倍累积该区 30 位，区外恒 0；区 0 ↔ 高 chunk） |
//! | `180..183` | 3 | `ba0..ba2`：B 的 chunk 累积器（同上） |
//! | `183..185` | 2 | `eq, lt`：位比较标志链（eq = 前缀位全等，lt = 已判定 x < B） |
//! | `185..188` | 3 | `xc0..xc2`：x 的 chunk 值（区 0/1/2 ↔ 高/中/低 chunk，全行常量见证列） |
//! | `188..192` | 4 | `s0..s3`：salt 的 4 个 u32 limb（全行常量见证列） |
//!
//! **预处理列**（7 列，[`BaseAir::preprocessed_trace`] 提供、setup 阶段
//! 承诺，行结构与电路同源锁定，见证不可篡改）：`z0, z1, z2`（行 ∈
//! 区 j 的指示子）、`e0, e1, e2`（区 j 末行（行 29/59/89）指示子）、
//! `bz`（行 ∈ 位区（行 0..89）指示子）。行区划分（30 行一区）由此
//! **精确钉死**，杜绝见证自选区长导致累积器 mod-p 环绕的攻击面。
//!
//! 行布局（固定 128 行）：行 `0..89` = 位区（t = 0，dummy 置换链）；
//! 行 `90..123` = 填充行（t = 0）；行 124 = start 行（t = 1，
//! inputs = label‖0，c = 0）；行 125/126/127 = 吸收块行（c = 1/2/3，
//! block = 词(x)/词(salt)/sentinel）。
//!
//! ## 约束列表（max degree = 3，仍来自 S-box x³）
//!
//! 1. **置换约束**（所有行）：与 note_opening 逐字相同（外部线性层
//!    起始，4+20+4 轮，`ending_full_rounds[3].post` 即该行置换输出）；
//! 2. **t 链**（与 note_opening 相同）：t 布尔、首行 t = 0、末行
//!    t = 1、单调（`t·(1−t') = 0`），g = t' − t 为唯一 0→1 转移指示
//!    （start 行进入标志）——首行 t = 0 封死「t≡1 伪造链」攻击；
//! 3. **链式吸收**（转移，g = 0）：rate 槽 `inputs'[i] = post[i] +
//!    block'[i]`（i < 8）、capacity 槽 `inputs'[i] = post[i]`（i ≥ 8）；
//! 4. **start 行**（转移，g = 1）：`inputs' = label‖0`；
//! 5. **计数器**：c1、c0 布尔（所有行）；填充行清零
//!    `(1−t)·c1 = (1−t)·c0 = 0`；进入 start（g = 1）`c1' = c0' = 0`；
//!    真实行递增（转移，t = 1）`c' = c + 1`；末行 `c = 3`——联立迫使
//!    真实区恰好 4 行（c 序列 0,1,2,3，超出则 c1/c0 布尔破坏）；
//! 6. **块内容钉死**（所有行）：记 ind1 = (1−c1)·c0、
//!    ind2 = c1·(1−c0)、ind3 = c1·c0，则
//!    `block = [ind1·xc2 + ind3, ind1·xc1, ind1·xc0, 0, ind2·s0, …, ind2·s3]`
//!    （块内 limb 顺序 = 词 0 的 LE 顺序 [c0, c1, c2] = 列
//!    [xc2, xc1, xc0] 反向）——c = 1 行吸收词(x) 的 3 个 chunk limb、
//!    c = 2 行吸收词(salt) 高 4 limb、c = 3 行吸收 sentinel‖零、
//!    c = 0（start 行）block = 0；
//! 7. **位/标志布尔**（所有行）：xb、bb、eq、lt 满足 b·(1−b) = 0；
//! 8. **位区初始化**（首行）：`xa0 = xb`、`ba0 = bb`、`eq = 1`、
//!    `lt = 0`（首行属区 0）；
//! 9. **chunk 累积**（转移，对 x/B 与区 j = 0,1,2）：
//!    `z_j'·(acc_j' − 2·acc_j − b') = 0` 与
//!    `(1−z_j')·acc_j' = 0`（区内 MSB 起加倍、区外复位为 0；进入
//!    区时自动 `acc' = b'`；z_j 为预处理常量，degree 2）；
//! 10. **比较链**（转移，degree 3，无守卫全域推进）：
//!     `eq' = eq·(1 − (xb'−bb')²)`、`lt' = lt + eq·bb'·(1−xb')`
//!     （沿 90 位 MSB 前序）；
//!
//! 10b. **位区外位值相等**（local，degree 2）：
//! `(1−bz)·(xb − bb) = 0`——位区外 d = 0 使比较链 10 自动冻结
//! （eq 不变、lt 增量项 eq·bb·(1−xb) = 0），同时杜绝在填充行
//! 伪造「胜负位」；bz 是预处理列（symbolic 口径 degree 1，故
//! 比较链本身不乘 bz 守卫以保 max degree 3）。
//! 11. **常量列冻结**（转移）：`xc_j' = xc_j`、`s_j' = s_j`；
//! 12. **绑定与终局**（所有行，local，由预处理指示子定位）：
//!     - `e_j·(xa_j − xc_j) = 0`——区 j 的 30 位累积末值 == chunk 列
//!       （**无环绕：累积中间值 < 2^k，末值 ≤ 2^30−1 < p，域等式即
//!       整数等式**；区 0/1/2 ↔ 高/中/低 chunk）；
//!     - `e_j·(ba_j − publics[2−j]) = 0`——B 的位分解对公开 chunk；
//!     - `e2·(lt + eq − 1) = 0`（行 89 终局：x < B ⇒ lt = 1、
//!       x = B ⇒ eq = 1、x > B ⇒ 两者皆 0 违规）；
//!     - 末行：t = 1、c = 3、`post[0..8] = publics[3..11]`（C 绑定）。
//!
//! ## 可靠性论证
//!
//! - **无环绕绑定（核心）**：预处理列把 90 个位行精确划分为 3 个
//!   30 行区；约束 9 的区内加倍累积在任意中间步取值 < 2^30 < p，域
//!   运算与整数运算一致；约束 12 的 e_j 绑定因此是整数等式——chunk
//!   值被其 30 位分解唯一确定。x 侧三 chunk 经约束 6 直接送入 sponge
//!   吸收（C 绑定），B 侧三 chunk 对 publics（B 绑定），整数
//!   `x = Σ xc_j·2^{30j}`、`B = Σ publics[j]·2^{30j}` 由此精确确立。
//! - **比较链防伪造**：eq/lt 虽是见证列，但首行值被钉死（约束 8）、
//!   每个转移值被约束 10 完全确定为前值与该位 x/b 位的函数
//!   （零自由度），位区外因 10b（d = 0）自动冻结；行 89 的
//!   `lt + eq = 1` 与 90 位 MSB 前序联立恰等价整数不等式 x ≤ B
//!   （第一个 xb ≠ bb 的位定胜负，前缀全等由 eq 携带）。位序列与
//!   整数的对应无 mod-p 介入（比较从不对位加权和求域和）。
//! - **B 不能换位分解**：bb 的每 chunk 30 位经无环绕累积 == publics
//!   chunk，整数唯一性 ⟹ bb 必须是整数 B 的 90 位分解。
//! - **块结构不可绕过**：计数器约束 5 迫使真实区恰好 4 行且
//!   c = 0,1,2,3 依次；约束 6 按 c 钉死每块内容（含 sentinel 与零
//!   填充）——相对 note_opening（块为自由见证）的实质增强。
//! - 其余（首行 t = 0、单调、label 锚定、置换可回溯性）与
//!   note_opening 论证相同。
//!
//! ## 诚实边界
//!
//! 非零知识（crate 根文档）：proof 泄露 witness openings，Phase 3
//! 前不修复；x/salt 可从 proof 复原，B/C 本就公开。

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{integers::QuotientMap, Dup, Field, PrimeCharacteristicRing, PrimeField32};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_koala_bear::{
    default_koalabear_poseidon2_16, GenericPoseidon2LinearLayersKoalaBear, KoalaBear,
    Poseidon2KoalaBear, KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, KOALABEAR_POSEIDON2_RC_16_INTERNAL,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2::{ExternalLayerConstants, GenericPoseidon2LinearLayers};
use p3_poseidon2_air::{
    generate_trace_rows, num_cols, FullRound, PartialRound, Poseidon2Cols, RoundConstants,
};
use p3_symmetric::{PaddingFreeSponge, Permutation, TruncatedPermutation};
use p3_uni_stark::{
    prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed, StarkConfig,
};
use vg_infra_crypto::keccak256;
use vg_infra_crypto::poseidon::{poseidon_note_commitment, to_field_le};
use vg_infra_crypto::Hash32;

use crate::ZkError;

/// 电路标识（Task 13 PlonkyProver 的 circuit@version 口径）。
pub const RANGE_CHECK_CIRCUIT_ID: &str = "range_check";
/// 电路版本（约束/配置变更时递增，proof 不跨版本兼容）。
///
/// v2：改 30-bit chunk 无环绕绑定，修复 v1 的 mod-p 同余漏洞
/// （64 位位和可超 p，域等式退化为同余，整数 x ≤ B 不可靠）。
pub const RANGE_CHECK_CIRCUIT_VERSION: u64 = 2;

/// Poseidon2 置换宽度（与 host 侧 sponge 规范一致，写死）。
const WIDTH: usize = 16;
/// sponge 速率（每块吸收 limb 数）。
const RATE: usize = 8;
/// S-box 幂次 d = 3（KoalaBear 预置）。
const SBOX_DEGREE: u64 = 3;
/// S-box 中间寄存器数（d=3 无需中间列）。
const SBOX_REGISTERS: usize = 0;
/// 每半全轮数（R_F = 8）。
const HALF_FULL_ROUNDS: usize = 4;
/// 部分轮数（R_P = 20）。
const PARTIAL_ROUNDS: usize = 20;
/// 域分隔标签（与 vg-infra-crypto poseidon 模块一致，勿改动）。
const DOMAIN_LABEL: &[u8] = b"vg:poseidon:v1";
/// 公开输入个数：B 三 chunk + C 八 limb。
const NUM_PUBLICS: usize = 11;
/// chunk 位数（无环绕基石：2^30 < p = 0x7F000001）。
const CHUNK_BITS: u32 = 30;
/// chunk 数（3 × 30 = 90 位 ⊃ u64）。
const NUM_CHUNKS: usize = 3;
/// 位区行数（= 90 位整数分解，MSB 在前）。
const BIT_ROWS: usize = NUM_CHUNKS * CHUNK_BITS as usize;
/// trace 高度（固定 128 = 2^7：90 位行 + 34 填充 + 4 真实行）。
const HEIGHT: usize = 128;
/// log2(HEIGHT)。
const HEIGHT_LOG: usize = 7;
/// 真实行数：start 行 + 3 个吸收块行。
const REAL_ROWS: usize = 4;
/// 填充行数（start 行之前，含 90 个位行）。
const PAD: usize = HEIGHT - REAL_ROWS;

/// 置换列区宽度（p3-poseidon2-air 同款列布局的 `num_cols`）。
const PERM_COLS: usize =
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
/// block[8] 起始下标。
const BLOCK_COL: usize = PERM_COLS;
/// t 标志列下标。
const T_COL: usize = PERM_COLS + RATE;
/// c1 列下标。
const C1_COL: usize = T_COL + 1;
/// c0 列下标。
const C0_COL: usize = C1_COL + 1;
/// xb 列下标。
const XB_COL: usize = C0_COL + 1;
/// bb 列下标。
const BB_COL: usize = XB_COL + 1;
/// xa0（区 0 = 高 chunk 累积器）列下标。
const XA0_COL: usize = BB_COL + 1;
/// ba0 列下标。
const BA0_COL: usize = XA0_COL + NUM_CHUNKS;
/// eq 列下标。
const EQ_COL: usize = BA0_COL + NUM_CHUNKS;
/// lt 列下标。
const LT_COL: usize = EQ_COL + 1;
/// xc0（chunk 值列区，0/1/2 ↔ 高/中/低）列下标。
const XC0_COL: usize = LT_COL + 1;
/// s0 列下标。
const S0_COL: usize = XC0_COL + NUM_CHUNKS;
/// 本电路总列宽。
const TOTAL_COLS: usize = S0_COL + 4;

// 预处理列下标。
/// z_j：行 ∈ 区 j。
const PP_Z: usize = 0;
/// e_j：区 j 末行（行 29/59/89）。
const PP_E: usize = NUM_CHUNKS;
/// bz：行 ∈ 位区（行 0..89）。
const PP_BZ: usize = PP_E + NUM_CHUNKS;
/// 预处理列总数。
const PP_COLS: usize = PP_BZ + 1;

// ---- StarkConfig 组装（与 note_opening 同款 two-adic 配置） ----

type F = KoalaBear;
type Perm = Poseidon2KoalaBear<WIDTH>;
type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, RATE>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, WIDTH>;
type ValMmcs =
    MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 2, 8>;
type Challenge = BinomialExtensionField<F, 4>;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
type Dft = Radix2DitParallel<F>;
type Pcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
/// 本电路的 STARK 配置类型。
type RangeConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// 组装 STARK 配置（确定性，参数与 note_opening 一致）。
fn range_config() -> RangeConfig {
    let perm: Perm = default_koalabear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters {
        log_blowup: 3,
        log_final_poly_len: 1,
        max_log_arity: 1,
        num_queries: 40,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 12,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    RangeConfig::new(pcs, challenger)
}

/// 域分隔 label 的 8 个 limb（与 host 侧 sponge 第 1 步一致）。
fn label_limbs() -> [KoalaBear; RATE] {
    let digest = keccak256(DOMAIN_LABEL);
    let limbs = to_field_le(&digest);
    let mut out = [KoalaBear::from_int(0u32); RATE];
    out.copy_from_slice(&limbs);
    out
}

/// 整数 v 的 3 个 30-bit chunk：`[c0, c1, c2]`（低→高，
/// `v = Σ c_j·2^{30j}`，各恒 < 2^30 < p）。
fn chunks30(v: u64) -> [u32; NUM_CHUNKS] {
    let mask = (1u64 << CHUNK_BITS) - 1;
    [
        (v & mask) as u32,
        ((v >> CHUNK_BITS) & mask) as u32,
        ((v >> (2 * CHUNK_BITS)) & mask) as u32,
    ]
}

/// x 的承诺词（词 0）：LE 装载 3 个 chunk 的 u32 值
/// （bytes 0..4 = c0、4..8 = c1、8..12 = c2、余零）。
fn x_word(x: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    for (j, c) in chunks30(x).iter().enumerate() {
        w[4 * j..4 * j + 4].copy_from_slice(&c.to_le_bytes());
    }
    w
}

/// salt 的承诺词（词 1）：低 16 字节零、高 16 字节 salt
/// （与 Note salt 词同构：`salt_word[16..] = salt`）。
fn salt_word(salt: &[u8; 16]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(salt);
    w
}

/// range 承诺的前像两词（编码规范见模块文档「承诺编码」小节，写死）。
pub fn range_commitment_parts(x: u64, salt: &[u8; 16]) -> [[u8; 32]; 2] {
    [x_word(x), salt_word(salt)]
}

/// host 侧便捷口径：C = Commit(x‖salt)（内部走
/// [`poseidon_note_commitment`]，供应用层对账）。
pub fn range_commitment(x: u64, salt: &[u8; 16]) -> Hash32 {
    poseidon_note_commitment(&range_commitment_parts(x, salt))
}

/// salt 的 4 个 u32 小端 limb（词 1 的第 4..8 limb）。
fn salt_limbs(salt: &[u8; 16]) -> [KoalaBear; 4] {
    let w = salt_word(salt);
    let limbs = to_field_le(&w);
    [limbs[4], limbs[5], limbs[6], limbs[7]]
}

/// AIR：range_check（结构见模块文档）。
#[derive(Debug, Clone)]
pub struct RangeCheckAir {
    /// 置换轮常数（与 `default_koalabear_poseidon2_16` 同源）。
    constants: RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    /// 域分隔 label limb。
    label: [KoalaBear; RATE],
}

impl RangeCheckAir {
    /// 构造 AIR。
    pub fn new() -> Self {
        let external = ExternalLayerConstants::new(
            KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL.to_vec(),
            KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL.to_vec(),
        );
        let constants =
            RoundConstants::<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>::try_from_layers(
                &external,
                &KOALABEAR_POSEIDON2_RC_16_INTERNAL,
            )
            .expect("p3-koala-bear 预置常量形状与本 AIR 参数一致（源码常量锁定）");
        Self {
            constants,
            label: label_limbs(),
        }
    }

    /// 预处理 trace（行结构与电路同源锁定，见模块文档）：
    /// 列 `[z0, z1, z2, e0, e1, e2, bz]`。
    fn build_preprocessed(&self) -> RowMajorMatrix<KoalaBear> {
        let mut values = vec![KoalaBear::from_int(0u32); HEIGHT * PP_COLS];
        for r in 0..HEIGHT {
            let zone = if r < BIT_ROWS {
                Some(r / CHUNK_BITS as usize)
            } else {
                None
            };
            for j in 0..NUM_CHUNKS {
                let z = usize::from(zone == Some(j));
                let e = usize::from(
                    zone == Some(j) && r % CHUNK_BITS as usize == CHUNK_BITS as usize - 1,
                );
                values[r * PP_COLS + PP_Z + j] = KoalaBear::from_int(z as u32);
                values[r * PP_COLS + PP_E + j] = KoalaBear::from_int(e as u32);
            }
            values[r * PP_COLS + PP_BZ] = KoalaBear::from_int(u32::from(r < BIT_ROWS));
        }
        RowMajorMatrix::new(values, PP_COLS)
    }
}

impl Default for RangeCheckAir {
    fn default() -> Self {
        Self::new()
    }
}

impl BaseAir<KoalaBear> for RangeCheckAir {
    fn width(&self) -> usize {
        TOTAL_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<KoalaBear>> {
        Some(self.build_preprocessed())
    }

    fn preprocessed_width(&self) -> usize {
        PP_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLICS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // 最高次仍为 S-box x³（3）：比较链 eq·(xb·bb)、块内容 ind·chunk
        // 与区指示子守卫乘积均为 degree ≤ 3（z/e/bz 是预处理常量）。
        Some(3)
    }
}

impl<AB> Air<AB> for RangeCheckAir
where
    AB: AirBuilder<F = KoalaBear>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        // 预处理窗口只借 builder，先拷出两行值（Var: Copy）再释放借用
        let (prep_local, prep_next): (Vec<AB::Var>, Vec<AB::Var>) = {
            let prep = builder.preprocessed();
            (prep.current_slice().to_vec(), prep.next_slice().to_vec())
        };

        // 1. 置换约束（所有行）
        let perm_local: &Poseidon2Cols<
            AB::Var,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = local[0..PERM_COLS].borrow();
        constrain_permutation(builder, perm_local, &self.constants);
        let out_local = &perm_local.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;

        // 公开输入（先拷贝以结束不可变借用）
        let publics: Vec<AB::PublicVar> = builder.public_values().to_vec();

        let one: AB::Expr = KoalaBear::from_int(1u32).into();
        let t_local: AB::Expr = local[T_COL].into();
        let c1: AB::Expr = local[C1_COL].into();
        let c0: AB::Expr = local[C0_COL].into();

        // 2. t 布尔 + 首行 t = 0（封死「t≡1 伪造链」攻击，同 note_opening）
        builder.assert_zero(t_local.clone() * (t_local.clone() - one.clone()));
        builder.when_first_row().assert_zero(local[T_COL]);

        // 10b. 位区外位值冻结为相等（xb = bb）：使比较链 10 在位区外
        // 自动冻结（d = 0），同时杜绝在填充行伪造「胜负位」
        builder.assert_zero(
            (one.clone() - prep_local[PP_BZ].into()) * (local[XB_COL].into() - local[BB_COL].into()),
        );

        // 5/7. 计数器与标志位布尔（所有行）
        for col in [C1_COL, C0_COL, XB_COL, BB_COL, EQ_COL, LT_COL] {
            let b: AB::Expr = local[col].into();
            builder.assert_zero(b.clone() * (b - one.clone()));
        }
        // 5. 填充行计数器清零：(1−t)·c1 = (1−t)·c0 = 0
        builder.assert_zero((one.clone() - t_local.clone()) * c1.clone());
        builder.assert_zero((one.clone() - t_local.clone()) * c0.clone());

        // 6. 块内容钉死（所有行）：
        // ind1 = (1−c1)·c0（c=1）、ind2 = c1·(1−c0)（c=2）、ind3 = c1·c0（c=3）
        let ind1 = (one.clone() - c1.clone()) * c0.clone();
        let ind2 = c1.clone() * (one.clone() - c0.clone());
        let ind3 = c1.clone() * c0.clone();
        // 词 0 的 LE limb 顺序 [c0, c1, c2] = 列 [xc2, xc1, xc0] 反向
        let xc_hi: AB::Expr = local[XC0_COL].into();
        let xc_mid: AB::Expr = local[XC0_COL + 1].into();
        let xc_lo: AB::Expr = local[XC0_COL + 2].into();
        builder.assert_zero(local[BLOCK_COL].into() - ind1.clone() * xc_lo.clone() - ind3.clone());
        builder.assert_zero(local[BLOCK_COL + 1].into() - ind1.clone() * xc_mid.clone());
        builder.assert_zero(local[BLOCK_COL + 2].into() - ind1.clone() * xc_hi.clone());
        // block[3] = 0（词 0 的零填充 limb）
        builder.assert_zero(local[BLOCK_COL + 3]);
        // block[4..8] = ind2·s_j（c=2 时 salt 的 4 limb）
        for j in 0..4 {
            let s_j: AB::Expr = local[S0_COL + j].into();
            builder.assert_zero(local[BLOCK_COL + 4 + j].into() - ind2.clone() * s_j);
        }

        // 12. 绑定与终局（local，由预处理指示子定位行 29/59/89）
        for j in 0..NUM_CHUNKS {
            let e_j = prep_local[PP_E + j];
            // x 侧：区 j 累积末值 == chunk 列（区 0/1/2 ↔ 高/中/低）
            builder.assert_zero(
                e_j.into() * (local[XA0_COL + j].into() - local[XC0_COL + j].into()),
            );
            // B 侧：区 j 累积末值 == publics chunk（高/中/低 ↔ [2]/[1]/[0]）
            builder
                .assert_zero(e_j.into() * (local[BA0_COL + j].into() - publics[NUM_CHUNKS - 1 - j].into()));
        }
        // 终局（行 89 = 区 2 末行）：lt + eq = 1
        builder.assert_zero(
            prep_local[PP_E + NUM_CHUNKS - 1].into()
                * (local[LT_COL].into() + local[EQ_COL].into() - one.clone()),
        );

        // 12b. 末行：t = 1、c = 3、C 公开绑定
        {
            let mut when_last = builder.when_last_row();
            when_last.assert_eq(local[T_COL], KoalaBear::from_int(1u32));
            for i in 0..RATE {
                when_last.assert_eq(out_local[i], publics[NUM_CHUNKS + i]);
            }
            when_last.assert_eq(local[C1_COL], KoalaBear::from_int(1u32));
            when_last.assert_eq(local[C0_COL], KoalaBear::from_int(1u32));
        }

        // 8. 位区初始化（首行属区 0）
        {
            let mut when_first = builder.when_first_row();
            when_first.assert_eq(local[XA0_COL], local[XB_COL]);
            when_first.assert_eq(local[BA0_COL], local[BB_COL]);
            when_first.assert_eq(local[EQ_COL], KoalaBear::from_int(1u32));
            when_first.assert_zero(local[LT_COL]);
        }

        // 3/4/5/9/10/11. 转移约束
        let next = main.next_slice();
        let perm_next: &Poseidon2Cols<
            AB::Var,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = next[0..PERM_COLS].borrow();
        let inputs_next = &perm_next.inputs;

        let t_next: AB::Expr = next[T_COL].into();
        let g = t_next.clone() - t_local.clone();
        let one_minus_g = one.clone() - g.clone();

        let mut when_transition = builder.when_transition();
        // 2. t 单调
        when_transition.assert_zero(local[T_COL] * (one.clone() - next[T_COL]));

        // 3. 链式吸收（g = 0）
        for i in 0..RATE {
            let chain = inputs_next[i] - out_local[i] - next[BLOCK_COL + i];
            when_transition.assert_zero(one_minus_g.clone() * chain);
        }
        for i in RATE..WIDTH {
            when_transition.assert_zero(one_minus_g.clone() * (inputs_next[i] - out_local[i]));
        }
        // 4. start 行（g = 1）：inputs = label‖0
        for (input_next, label_i) in inputs_next.iter().zip(self.label) {
            when_transition.assert_zero(g.clone() * (*input_next - label_i));
        }
        for input_next in inputs_next.iter().take(WIDTH).skip(RATE) {
            when_transition.assert_zero(g.clone() * *input_next);
        }

        // 5. 计数器：进入 start 清零、真实行递增
        when_transition.assert_zero(g.clone() * next[C1_COL]);
        when_transition.assert_zero(g.clone() * next[C0_COL]);
        let c_local = c1 * KoalaBear::from_int(2u32) + c0.clone();
        let c1n: AB::Expr = next[C1_COL].into();
        let c0n: AB::Expr = next[C0_COL].into();
        let c_next = c1n * KoalaBear::from_int(2u32) + c0n;
        when_transition.assert_zero(t_local.clone() * (c_next - c_local - one.clone()));

        // 9. chunk 累积（区内加倍、区外复位 0；z_j 为预处理常量）
        let two = KoalaBear::from_int(2u32);
        for j in 0..NUM_CHUNKS {
            let z_j: AB::Expr = prep_next[PP_Z + j].into();
            let one_minus_z = one.clone() - z_j.clone();
            for (acc, bit) in [(XA0_COL + j, XB_COL), (BA0_COL + j, BB_COL)] {
                let a: AB::Expr = local[acc].into();
                let b_n: AB::Expr = next[bit].into();
                let a_n: AB::Expr = next[acc].into();
                when_transition.assert_zero(z_j.clone() * (a_n.clone() - a * two - b_n));
                when_transition.assert_zero(one_minus_z.clone() * a_n);
            }
        }

        // 10. 比较链（无守卫推进：d²∈{0,1}，eq' = eq·(1−d²)、
        // lt' = lt + eq·bb'·(1−xb')，degree 3）。位区外的推进无害：
        // 下方 10b 强制位区外 xb = bb（d = 0 ⟹ eq/lt 冻结，
        // lt 增量项 eq·bb·(1−xb) = 0），故比较链可全域裸跑而语义不变。
        let eq: AB::Expr = local[EQ_COL].into();
        let lt: AB::Expr = local[LT_COL].into();
        let xb_n: AB::Expr = next[XB_COL].into();
        let bb_n: AB::Expr = next[BB_COL].into();
        let d = xb_n.clone() - bb_n.clone();
        let d_sq = d.clone() * d;
        when_transition.assert_zero(next[EQ_COL] - eq.clone() * (one.clone() - d_sq));
        when_transition.assert_zero(next[LT_COL] - lt.clone() - eq.clone() * bb_n * (one - xb_n));

        // 11. 常量列冻结（chunk 值与 salt limb）
        for col in [
            XC0_COL,
            XC0_COL + 1,
            XC0_COL + 2,
            S0_COL,
            S0_COL + 1,
            S0_COL + 2,
            S0_COL + 3,
        ] {
            when_transition.assert_zero(next[col] - local[col]);
        }
    }
}

/// 按行重算一次完整 Poseidon2 置换（与 note_opening 逐字相同）。
fn constrain_permutation<AB: AirBuilder<F = KoalaBear>>(
    builder: &mut AB,
    cols: &Poseidon2Cols<
        AB::Var,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
    constants: &RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
) {
    let mut state: [AB::Expr; WIDTH] = cols.inputs.map(Into::into);

    GenericPoseidon2LinearLayersKoalaBear::external_linear_layer(&mut state);

    for (round, rc) in cols
        .beginning_full_rounds
        .iter()
        .zip(constants.beginning_full_round_constants())
    {
        constrain_full_round(builder, &mut state, round, rc);
    }
    for (round, rc) in cols
        .partial_rounds
        .iter()
        .zip(constants.partial_round_constants())
    {
        constrain_partial_round(builder, &mut state, round, rc);
    }
    for (round, rc) in cols
        .ending_full_rounds
        .iter()
        .zip(constants.ending_full_round_constants())
    {
        constrain_full_round(builder, &mut state, round, rc);
    }
}

/// 全轮：+rc → x³ → 外部线性层，逐元 assert 到 post 列。
fn constrain_full_round<AB: AirBuilder<F = KoalaBear>>(
    builder: &mut AB,
    state: &mut [AB::Expr; WIDTH],
    round: &FullRound<AB::Var, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    rc: &[KoalaBear; WIDTH],
) {
    for (s, r) in state.iter_mut().zip(rc.iter()) {
        *s += r.dup();
        *s = s.clone().cube();
    }
    GenericPoseidon2LinearLayersKoalaBear::external_linear_layer(state);
    for (s, post) in state.iter_mut().zip(round.post) {
        builder.assert_eq(s.clone(), post);
        *s = post.into();
    }
}

/// 部分轮：state[0] +rc → x³ → assert 到 post_sbox 列 → 内部线性层。
fn constrain_partial_round<AB: AirBuilder<F = KoalaBear>>(
    builder: &mut AB,
    state: &mut [AB::Expr; WIDTH],
    round: &PartialRound<AB::Var, SBOX_DEGREE, SBOX_REGISTERS>,
    rc: &KoalaBear,
) {
    state[0] += rc.dup();
    state[0] = state[0].clone().cube();
    builder.assert_eq(state[0].clone(), round.post_sbox);
    state[0] = round.post_sbox.into();
    GenericPoseidon2LinearLayersKoalaBear::internal_linear_layer(state);
}

// ---- 见证生成与公开 API ----

/// 见证与公开输入（prove/verify 内部使用）。
struct Witness {
    trace: RowMajorMatrix<KoalaBear>,
    publics: [KoalaBear; NUM_PUBLICS],
}

/// 构造 trace 与公开输入（结构见模块文档「AIR 结构」小节）。
fn build_witness(x: u64, salt: &[u8; 16], bound: u64) -> Witness {
    // ---- 位区（行 0..89）：90 位整数 MSB 前序 + 分区累积 + 比较链 ----
    let mut xb_bits = [0u32; BIT_ROWS];
    let mut bb_bits = [0u32; BIT_ROWS];
    // xa[j]/ba[j]：区 j 的累积器（区 0 ↔ 高 chunk）
    let mut xa = [KoalaBear::from_int(0u32); NUM_CHUNKS];
    let mut ba = [KoalaBear::from_int(0u32); NUM_CHUNKS];
    let mut xaccs = [[KoalaBear::from_int(0u32); NUM_CHUNKS]; BIT_ROWS];
    let mut baccs = [[KoalaBear::from_int(0u32); NUM_CHUNKS]; BIT_ROWS];
    let mut eqs = [KoalaBear::from_int(0u32); BIT_ROWS];
    let mut lts = [KoalaBear::from_int(0u32); BIT_ROWS];
    let two = KoalaBear::from_int(2u32);
    let one_f = KoalaBear::from_int(1u32);
    // i ∈ 0..90，超过 64 的位恒 0（u64 < 2^90）
    let zbit = |v: u64, i: u32| {
        let b = if i < 64 { (v >> i) & 1 } else { 0 };
        KoalaBear::from_int(b as u32)
    };
    for r in 0..BIT_ROWS {
        // 行 r 承载 90 位整数的第 (89−r) 位（MSB 在前）
        let i = (BIT_ROWS - 1 - r) as u32;
        let xb = if i < 64 { (x >> i) & 1 } else { 0 };
        let bb = if i < 64 { (bound >> i) & 1 } else { 0 };
        let zone = r / CHUNK_BITS as usize;
        // 约束 8/10 的诚实计算
        if r == 0 {
            eqs[0] = one_f;
            lts[0] = KoalaBear::from_int(0u32);
        } else {
            let d = zbit(x, i) - zbit(bound, i);
            eqs[r] = eqs[r - 1] * (one_f - d * d);
            lts[r] = if eqs[r - 1] == one_f && xb == 0 && bb == 1 {
                one_f
            } else {
                lts[r - 1]
            };
        }
        // 约束 9 的诚实计算：区内加倍（区首 = 位值）
        if r % CHUNK_BITS as usize == 0 {
            xa[zone] = zbit(x, i);
            ba[zone] = zbit(bound, i);
        } else {
            xa[zone] = xa[zone] * two + zbit(x, i);
            ba[zone] = ba[zone] * two + zbit(bound, i);
        }
        xb_bits[r] = xb as u32;
        bb_bits[r] = bb as u32;
        // 每行只保留本区累积器，其余区恒 0（约束 9 的区外复位要求；
        // 区末值已由 e_j 绑定消费，无需在后续行冻结携带）
        xaccs[r] = [KoalaBear::from_int(0u32); NUM_CHUNKS];
        baccs[r] = [KoalaBear::from_int(0u32); NUM_CHUNKS];
        xaccs[r][zone] = xa[zone];
        baccs[r][zone] = ba[zone];
    }

    // ---- 常量 chunk / salt 列（列序 [高, 中, 低]） ----
    let x_chunks = chunks30(x); // [c0, c1, c2] 低→高
    let chunk_cols = [
        KoalaBear::from_int(x_chunks[2]),
        KoalaBear::from_int(x_chunks[1]),
        KoalaBear::from_int(x_chunks[0]),
    ];
    let s = salt_limbs(salt);

    // ---- 吸收块（3 块）：词(x) / 词(salt) / sentinel‖零 ----
    let blocks: Vec<[KoalaBear; RATE]> = {
        let w0 = x_word(x);
        let w1 = salt_word(salt);
        let mut limbs = to_field_le(&w0);
        limbs.extend(to_field_le(&w1));
        limbs.push(KoalaBear::from_int(1u32));
        while !limbs.len().is_multiple_of(RATE) {
            limbs.push(KoalaBear::from_int(0u32));
        }
        limbs
            .chunks_exact(RATE)
            .map(|c| c.try_into().expect("chunks_exact 保证 8 limb"))
            .collect()
    };
    debug_assert_eq!(blocks.len(), 3);

    // ---- 置换链：PAD 行 dummy（零状态链）→ start（label）→ 3 块吸收 ----
    let perm_host = default_koalabear_poseidon2_16();
    let label = label_limbs();

    let mut inputs: Vec<[KoalaBear; WIDTH]> = Vec::with_capacity(HEIGHT);
    let mut dummy = [KoalaBear::from_int(0u32); WIDTH];
    for _ in 0..PAD {
        inputs.push(dummy);
        perm_host.permute_mut(&mut dummy);
    }
    let mut state = [KoalaBear::from_int(0u32); WIDTH];
    state[..RATE].copy_from_slice(&label);
    inputs.push(state);
    perm_host.permute_mut(&mut state);
    for block in &blocks {
        for i in 0..RATE {
            state[i] += block[i];
        }
        inputs.push(state);
        perm_host.permute_mut(&mut state);
    }
    debug_assert_eq!(inputs.len(), HEIGHT);

    // ---- 公开输入：[B_c0, B_c1, B_c2, C×8] ----
    let b_chunks = chunks30(bound);
    let mut publics = [KoalaBear::from_int(0u32); NUM_PUBLICS];
    for (j, c) in b_chunks.iter().enumerate() {
        publics[j] = KoalaBear::from_int(*c);
    }
    publics[NUM_CHUNKS..NUM_PUBLICS].copy_from_slice(&state[..RATE]);

    // ---- 填充置换列并拼装全列 trace ----
    let air = RangeCheckAir::new();
    let perm_matrix = generate_trace_rows::<
        KoalaBear,
        GenericPoseidon2LinearLayersKoalaBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, &air.constants, 0);

    let mut values = vec![KoalaBear::from_int(0u32); HEIGHT * TOTAL_COLS];
    for r in 0..HEIGHT {
        let base = r * TOTAL_COLS;
        let src = &perm_matrix.values[r * PERM_COLS..(r + 1) * PERM_COLS];
        values[base..base + PERM_COLS].copy_from_slice(src);
        let real = r >= PAD;
        values[base + T_COL] = KoalaBear::from_int(u32::from(real));
        // 计数器：填充/start 行 0，块行 1/2/3
        let c = if r < PAD + 1 { 0 } else { (r - PAD) as u32 };
        values[base + C1_COL] = KoalaBear::from_int(c >> 1);
        values[base + C0_COL] = KoalaBear::from_int(c & 1);
        // 位区列：位/累积器/标志诚实填；行 90+ 累积器区外复位为 0，
        // eq/lt 冻结在行 89 终值（约束 10 的位区外冻结要求）
        values[base + XB_COL] = KoalaBear::from_int(if r < BIT_ROWS { xb_bits[r] } else { 0 });
        values[base + BB_COL] = KoalaBear::from_int(if r < BIT_ROWS { bb_bits[r] } else { 0 });
        for j in 0..NUM_CHUNKS {
            let xa_j = if r < BIT_ROWS { xaccs[r][j] } else { KoalaBear::from_int(0u32) };
            let ba_j = if r < BIT_ROWS { baccs[r][j] } else { KoalaBear::from_int(0u32) };
            values[base + XA0_COL + j] = xa_j;
            values[base + BA0_COL + j] = ba_j;
        }
        let eq_r = if r < BIT_ROWS { eqs[r] } else { eqs[BIT_ROWS - 1] };
        let lt_r = if r < BIT_ROWS { lts[r] } else { lts[BIT_ROWS - 1] };
        values[base + EQ_COL] = eq_r;
        values[base + LT_COL] = lt_r;
        // 常量 chunk / salt 列（全行相同）
        for j in 0..NUM_CHUNKS {
            values[base + XC0_COL + j] = chunk_cols[j];
        }
        values[base + S0_COL..base + S0_COL + 4].copy_from_slice(&s);
        // block 列：块行 = 对应吸收块，其余全零
        if real && r > PAD {
            let block = &blocks[r - PAD - 1];
            values[base + BLOCK_COL..base + BLOCK_COL + RATE].copy_from_slice(block);
        }
    }

    Witness {
        trace: RowMajorMatrix::new(values, TOTAL_COLS),
        publics,
    }
}

/// range_check 证明输出。
///
/// - `proof`：postcard 序列化的 `p3_uni_stark::Proof<RangeConfig>` 字节
///   （配置随 [`RANGE_CHECK_CIRCUIT_VERSION`] 锁定）；
/// - `public_limbs`：公开输入 11 个 canonical u32 limb，顺序
///   `[B_c0, B_c1, B_c2, C_0..C_7]`（B chunk 恒 < 2^30 canonical 无
///   归约；整数 `B = Σ B_cj·2^{30j}`；C 小端拼接即 32B 承诺）。
///
/// 独立于 note_opening 的 `ProofOutput`（后者 `public_limbs` 定长 8，
/// 本电路 11 个公开值，泛化改动会破坏 note_opening 公开 API，故新建）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeProofOutput {
    /// 证明字节（postcard）。
    pub proof: Vec<u8>,
    /// 公开输入（[B_c0, B_c1, B_c2, C×8]）。
    pub public_limbs: [u32; NUM_PUBLICS],
}

/// 为 (x, salt, bound) 计算 range_check 证明。
///
/// 语句：90 位（3 chunk × 30 位）分解精确重建 x ∧ 整数 x ≤ B ∧
/// C = Commit(x‖salt)。x > bound 时返回 [`ZkError::InvalidWitness`]
/// （见证必违反约束，电路外前置拦截不 panic）。
pub fn prove_range_check(
    x: u64,
    salt: &[u8; 16],
    bound: u64,
) -> Result<RangeProofOutput, ZkError> {
    if x > bound {
        return Err(ZkError::InvalidWitness(format!(
            "x ({x}) 超过上界 bound ({bound})，语句为假"
        )));
    }
    let witness = build_witness(x, salt, bound);
    let config = range_config();
    let air = RangeCheckAir::new();
    let publics: Vec<KoalaBear> = witness.publics.to_vec();
    let (pp, _vk) = setup_preprocessed(&config, &air, HEIGHT_LOG)
        .expect("本 AIR 定义 7 列预处理列，setup 应返回 Some");
    let proof = prove_with_preprocessed(&config, &air, witness.trace, &publics, Some(&pp));
    let bytes = postcard::to_allocvec(&proof).map_err(|e| ZkError::Serialization(e.to_string()))?;
    let mut public_limbs = [0u32; NUM_PUBLICS];
    for (i, v) in witness.publics.iter().enumerate() {
        public_limbs[i] = v.as_canonical_u32();
    }
    Ok(RangeProofOutput {
        proof: bytes,
        public_limbs,
    })
}

/// 验证 range_check 证明（publics 取 `output.public_limbs`）。
///
/// 任何篡改（证明字节或公开 limb）返回 false，不 panic。预处理列的
/// verifier key 由 `setup_preprocessed` 确定性重建并经 `OnceLock`
/// 缓存（AIR/config 全确定性，跨调用不变）。
pub fn verify_range_check(output: &RangeProofOutput) -> bool {
    let Ok(proof) = postcard::from_bytes(&output.proof) else {
        return false;
    };
    let publics: Vec<KoalaBear> = output
        .public_limbs
        .iter()
        .map(|l| KoalaBear::from_int(*l))
        .collect();
    let config = range_config();
    let air = RangeCheckAir::new();
    verify_with_preprocessed(&config, &air, &proof, &publics, Some(range_vk())).is_ok()
}

/// 预处理 verifier key 的进程级缓存（AIR/config 全确定性）。
fn range_vk() -> &'static p3_uni_stark::PreprocessedVerifierKey<RangeConfig> {
    static VK: std::sync::OnceLock<p3_uni_stark::PreprocessedVerifierKey<RangeConfig>> =
        std::sync::OnceLock::new();
    VK.get_or_init(|| {
        let config = range_config();
        let air = RangeCheckAir::new();
        setup_preprocessed(&config, &air, HEIGHT_LOG)
            .expect("本 AIR 定义 7 列预处理列，setup 应返回 Some")
            .1
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// KoalaBear 素数（无环绕论证与恶意构造用）。
    const P: u64 = 0x7F00_0001;

    /// 黄金参数：x、salt、B（bound）。
    const GOLDEN_X: u64 = 0x1FFDEADBEAF;
    const GOLDEN_SALT: [u8; 16] = [
        0x33, 0x44, 0x55, 0x66, 0xC0, 0xFF, 0xEE, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77,
    ];
    const GOLDEN_BOUND: u64 = 0xFFFF_FFFF_FFFF;

    /// 黄金承诺 hex（字面 fixture，首次由 host 计算后锁定）。
    const GOLDEN_C_HEX: &str = "7bb4cd57d124f91a01e63c2ea2c9314a2f0acb3085dac6085ce8e82dff487f12";

    /// 黄金 C 的 8 个 u32 小端 limb。
    fn golden_c_limbs() -> [u32; 8] {
        let bytes = hex::decode(GOLDEN_C_HEX).unwrap();
        (0..8)
            .map(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    #[test]
    fn golden_range_commitment() {
        // 无环绕前提自检：2^30 < p
        const _: () = assert!(1u64 << 30 < P, "无环绕原则要求 2^30 < p");

        // 前置对齐：host 侧承诺 == 黄金 C
        assert_eq!(
            range_commitment(GOLDEN_X, &GOLDEN_SALT).as_hex(),
            GOLDEN_C_HEX,
            "host 侧承诺必须先与 golden fixture 对齐"
        );

        let start = Instant::now();
        let output = prove_range_check(GOLDEN_X, &GOLDEN_SALT, GOLDEN_BOUND)
            .expect("黄金见证 prove 应成功");
        let prove_secs = start.elapsed().as_secs_f64();

        let start = Instant::now();
        assert!(verify_range_check(&output), "黄金证明 verify 必须 true");
        let verify_secs = start.elapsed().as_secs_f64();

        // publics = [B_c0, B_c1, B_c2, C×8]（chunk 恒 < 2^30 canonical）
        for (j, c) in chunks30(GOLDEN_BOUND).iter().enumerate() {
            assert_eq!(output.public_limbs[j], *c, "B chunk {j} 应 canonical 装载");
        }
        assert_eq!(&output.public_limbs[NUM_CHUNKS..], &golden_c_limbs());
        println!("golden prove: {prove_secs:.2}s, verify: {verify_secs:.2}s");
    }

    #[test]
    fn x_below_bound_passes() {
        // x 远小于 B / x = B−1 / x = B（相等边界通过）/ u64 极值组
        let salt = [0xABu8; 16];
        let bound: u64 = 1 << 40;
        for x in [0u64, 1, bound - 1, bound] {
            let output = prove_range_check(x, &salt, bound).expect("x ≤ B 应 prove 成功");
            assert!(verify_range_check(&output), "x = {x} ≤ B 的证明应 verify true");
        }
        // B = u64::MAX（三 chunk 全 0x3FFFFFFF）：x = B、x = B−1 通过
        let output = prove_range_check(u64::MAX, &salt, u64::MAX).expect("x = B = u64::MAX 应成功");
        assert!(verify_range_check(&output));
        let output = prove_range_check(u64::MAX - 1, &salt, u64::MAX - 1).unwrap();
        assert!(verify_range_check(&output));
        // x = u64::MAX > B−1 拒绝
        let err = prove_range_check(u64::MAX, &salt, u64::MAX - 1)
            .expect_err("x = u64::MAX > B−1 必须被拒绝");
        assert!(matches!(err, ZkError::InvalidWitness(_)));
    }

    #[test]
    fn x_above_bound_rejected() {
        let salt = [0xCDu8; 16];
        let bound: u64 = 1 << 40;
        // 语句为假：prove 前置拦截返回 InvalidWitness（不 panic）
        for x in [bound + 1, u64::MAX] {
            let err = prove_range_check(x, &salt, bound).expect_err("x > B 必须被拒绝");
            assert!(matches!(err, ZkError::InvalidWitness(_)));
        }
        // 大 x 的合法证明（大 B）对小 B 的 publics 验证 → false
        let output = prove_range_check(u64::MAX, &salt, u64::MAX).expect("x = B = u64::MAX 应成功");
        assert!(verify_range_check(&output));
        let mut small_b = output.clone();
        for j in 0..NUM_CHUNKS {
            small_b.public_limbs[j] = 0; // B' = 0 < x
        }
        assert!(
            !verify_range_check(&small_b),
            "大 x 的证明对小 B 的 publics 必须 false"
        );
    }

    #[test]
    fn tampered_publics_fail() {
        let output = prove_range_check(GOLDEN_X, &GOLDEN_SALT, GOLDEN_BOUND).unwrap();
        assert!(verify_range_check(&output));

        // 篡改 C 任一 limb → false
        for i in NUM_CHUNKS..NUM_PUBLICS {
            let mut tampered = output.clone();
            tampered.public_limbs[i] ^= 1;
            assert!(!verify_range_check(&tampered), "篡改 C limb {i} 必须 false");
        }
        // 篡改 B 中 chunk（publics[1]）清零 → B' = 0x3FFFFFFF ≪
        // x = 0x1FFDEADBEAF，篡改后必违反 x ≤ B'
        let mut tampered = output.clone();
        tampered.public_limbs[1] = 0;
        assert!(
            !verify_range_check(&tampered),
            "篡改 B 中 chunk 后 B' < x 必须 false"
        );
        // B 低 chunk（publics[0]）篡改为 0：位重建不再匹配 publics
        let mut tampered = output.clone();
        tampered.public_limbs[0] = 0;
        assert!(!verify_range_check(&tampered), "篡改 B 低 chunk 必须 false");
    }

    #[test]
    fn prove_roundtrip_is_repeatable() {
        let first = prove_range_check(GOLDEN_X, &GOLDEN_SALT, GOLDEN_BOUND).unwrap();
        let second = prove_range_check(GOLDEN_X, &GOLDEN_SALT, GOLDEN_BOUND).unwrap();
        assert!(verify_range_check(&first));
        assert!(verify_range_check(&second));
        assert_eq!(first.public_limbs, second.public_limbs);
    }

    #[test]
    fn tampered_proof_bytes_fail() {
        let mut output = prove_range_check(GOLDEN_X, &GOLDEN_SALT, GOLDEN_BOUND).unwrap();
        if let Some(b) = output.proof.last_mut() {
            *b ^= 0xFF;
        }
        assert!(!verify_range_check(&output));
    }

    /// 见证 publics 与 host 承诺一致性 + B chunk 整数重建（快速回归）。
    #[test]
    fn witness_publics_match_host_commitment() {
        for (x, salt, bound) in [
            (GOLDEN_X, GOLDEN_SALT, GOLDEN_BOUND),
            (0u64, [0u8; 16], u64::MAX),
            (u64::MAX, [0xFF; 16], u64::MAX),
            (42, [7; 16], 100),
        ] {
            let c = range_commitment(x, &salt);
            let expected: Vec<u32> = (0..8)
                .map(|i| u32::from_le_bytes(c.as_bytes()[4 * i..4 * i + 4].try_into().unwrap()))
                .collect();
            let witness = build_witness(x, &salt, bound);
            let got: Vec<u32> = witness.publics[NUM_CHUNKS..]
                .iter()
                .map(|e| e.as_canonical_u32())
                .collect();
            assert_eq!(got, expected, "x = {x} 的 C limb 必须与 host 一致");
            // B chunk publics 整数重建 bound（无归约失真）
            let b_int: u64 = (0..NUM_CHUNKS)
                .map(|j| (witness.publics[j].as_canonical_u32() as u64) << (CHUNK_BITS * j as u32))
                .sum();
            assert_eq!(b_int, bound, "B chunk publics 必须整数重建 bound");
        }
    }

    /// 对照组：诚实 witness 通过 debug 约束校验路径。
    #[test]
    fn honest_witness_passes_constraint_check() {
        use p3_air::check_constraints;
        let witness = build_witness(GOLDEN_X, &GOLDEN_SALT, GOLDEN_BOUND);
        let publics: Vec<KoalaBear> = witness.publics.to_vec();
        let air = RangeCheckAir::new();
        check_constraints(&air, &witness.trace, &publics);
    }

    /// 恶意 trace 回归 1（v1 mod-p 同余漏洞的 B 侧攻击，返工验收）：
    /// B = 100、承诺 x = 2^32，攻击者取 90 位整数 B' = 100 + p 的位
    /// 分解（90 位加权和 ≡ 100 (mod p)），期望骗过 B 绑定。
    ///
    /// 新约束下必不满足：bb 的位被**分区**累积（区 j 内 30 位加倍，
    /// 中间值 < 2^30 < p，无环绕），三个 chunk 末值 == B' 的 chunk
    /// 分解，而 e_j 绑定要求其 == publics 的 chunk 分解（100 →
    /// [100, 0, 0]）；B' 的 chunk 分解 ≠ [100, 0, 0]（100 + p 的
    /// 低 chunk = 100 + p − 2^31 + 2^30 ≠ 100），整数层面直接失配，
    /// mod-p 无可乘之机。
    #[test]
    fn malicious_modp_bound_bits_rejected() {
        use p3_air::check_constraints;
        let x = 1u64 << 32; // 承诺中的 x（远大于 100）
        let bound_attack = 100 + P; // B' = 100 + p < 2^64
        let salt = [0x99u8; 16];
        // 攻击 trace：bb 位/累积器/比较链 = B' 的诚实计算
        let witness = build_witness(x, &salt, bound_attack);
        // publics 换成真 B = 100 的 chunk（C 部分不动）
        let mut publics = witness.publics;
        for (j, c) in chunks30(100).iter().enumerate() {
            publics[j] = KoalaBear::from_int(*c);
        }
        let trace = RowMajorMatrix::new(witness.trace.values, TOTAL_COLS);
        let publics: Vec<KoalaBear> = publics.to_vec();
        let air = RangeCheckAir::new();
        let result = std::panic::catch_unwind(|| {
            check_constraints(&air, &trace, &publics);
        });
        assert!(
            result.is_err(),
            "mod-p 同余形态的 B 位分解必须被无环绕 chunk 绑定拒绝"
        );
    }

    /// 恶意 trace 回归 2（mod-p 同余攻击的 x 侧）：位分解取
    /// x' = x + p（90 位加权和 ≡ x (mod p)），期望同时满足「x' ≤ B」
    /// 与 chunk 绑定。同样被无环绕绑定拒绝：x' 的 chunk 分解 ≠
    /// 承诺词中的 x chunk 列，e_j 绑定整数失配。
    #[test]
    fn malicious_modp_x_bits_rejected() {
        use p3_air::check_constraints;
        let x = 1u64 << 32;
        let x_attack = x + P; // < 2^64，与 x 同余 mod p
        let bound = u64::MAX; // x' ≤ B 显然成立，攻击点仅在 x 绑定
        let salt = [0x99u8; 16];
        // 位/累积器/比较链取 x' 的诚实计算，但 chunk 列（与 C 绑定）
        // 覆写回承诺词的 x chunk —— 整数失配暴露攻击
        let witness = build_witness(x_attack, &salt, bound);
        let mut values = witness.trace.values.clone();
        let chunk_cols = [
            KoalaBear::from_int(chunks30(x)[2]),
            KoalaBear::from_int(chunks30(x)[1]),
            KoalaBear::from_int(chunks30(x)[0]),
        ];
        for r in 0..HEIGHT {
            for j in 0..NUM_CHUNKS {
                values[r * TOTAL_COLS + XC0_COL + j] = chunk_cols[j];
            }
        }
        let trace = RowMajorMatrix::new(values, TOTAL_COLS);
        let publics: Vec<KoalaBear> = witness.publics.to_vec();
        let air = RangeCheckAir::new();
        let result = std::panic::catch_unwind(|| {
            check_constraints(&air, &trace, &publics);
        });
        assert!(
            result.is_err(),
            "mod-p 同余形态的 x 位分解必须被无环绕 chunk 绑定拒绝"
        );
    }

    /// 恶意 trace 回归 3：位重建断裂（翻转一个 xb 位不更新累积器）。
    #[test]
    fn malicious_bit_reconstruction_rejected() {
        use p3_air::check_constraints;
        let witness = build_witness(GOLDEN_X, &GOLDEN_SALT, GOLDEN_BOUND);
        let mut values = witness.trace.values.clone();
        // 位区内某行的 xb 翻转（仍布尔），该 chunk 累积链断裂
        let r = 5;
        values[r * TOTAL_COLS + XB_COL] =
            KoalaBear::from_int(1u32) - values[r * TOTAL_COLS + XB_COL];
        let trace = RowMajorMatrix::new(values, TOTAL_COLS);
        let publics: Vec<KoalaBear> = witness.publics.to_vec();
        let air = RangeCheckAir::new();
        let result = std::panic::catch_unwind(|| {
            check_constraints(&air, &trace, &publics);
        });
        assert!(result.is_err(), "位重建断裂的 trace 必须被拒绝");
    }

    /// 恶意 trace 回归 4：伪造 lt 标志（x > B 却在中途强置 lt = 1）。
    ///
    /// 构造：x = u64::MAX > B = 0，所有位 x_i = 1, b_i = 0；从行 1 起
    /// 把 lt 置 1——若无约束 10 的 lt 转移钉死（前值 + eq·bb'·(1−xb')），
    /// 末行 lt + eq = 1 将被「蒙混」通过。
    #[test]
    fn malicious_forged_lt_flag_rejected() {
        use p3_air::check_constraints;
        let x = u64::MAX;
        let bound = 0u64;
        let salt = [0x99u8; 16];
        let witness = build_witness(x, &salt, bound);
        let mut values = witness.trace.values.clone();
        for r in 1..BIT_ROWS {
            values[r * TOTAL_COLS + LT_COL] = KoalaBear::from_int(1u32);
        }
        let trace = RowMajorMatrix::new(values, TOTAL_COLS);
        let publics: Vec<KoalaBear> = witness.publics.to_vec();
        let air = RangeCheckAir::new();
        let result = std::panic::catch_unwind(|| {
            check_constraints(&air, &trace, &publics);
        });
        assert!(result.is_err(), "伪造 lt 标志的 trace 必须被拒绝");
    }

    /// 恶意 trace 回归 5：伪造 B 位（bb 换成小 B' 的位但 publics 不变）。
    #[test]
    fn malicious_forged_bound_bits_rejected() {
        use p3_air::check_constraints;
        // 诚实见证：x = 5, B = 100；篡改：bb 位与累积器整体换成 B' = 0
        let x = 5u64;
        let bound = 100u64;
        let salt = [0x11u8; 16];
        let witness = build_witness(x, &salt, bound);
        let mut values = witness.trace.values.clone();
        for r in 0..BIT_ROWS {
            let base = r * TOTAL_COLS;
            values[base + BB_COL] = KoalaBear::from_int(0u32);
            for j in 0..NUM_CHUNKS {
                values[base + BA0_COL + j] = KoalaBear::from_int(0u32);
            }
        }
        let trace = RowMajorMatrix::new(values, TOTAL_COLS);
        let publics: Vec<KoalaBear> = witness.publics.to_vec();
        let air = RangeCheckAir::new();
        let result = std::panic::catch_unwind(|| {
            check_constraints(&air, &trace, &publics);
        });
        assert!(result.is_err(), "伪造 B 位的 trace 必须被拒绝");
    }
}
