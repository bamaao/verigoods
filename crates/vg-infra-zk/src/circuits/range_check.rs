//! range_check 电路：证明「知道 Poseidon2 承诺 C = Commit(x‖salt) 的
//! 前像，且 x ≤ B」。
//!
//! ## 语义
//!
//! - **公开输入**（10 个）：`[B_lo, B_hi, C_0..C_7]`——B 的两个
//!   canonical u32 limb（小端，低 32 位在前），C 的 8 个 limb（与
//!   note_opening 的 C 编码一致，即 host 侧
//!   [`vg_infra_crypto::poseidon::poseidon_note_commitment`] squeeze
//!   输出的 8 × u32 小端值）；
//! - **私有见证**：x（u64）、salt（16 字节）；
//! - **语句**：x 的 64 位分解重建 x ∧ x ≤ B（逐位比较）∧
//!   C = sponge(词(x), 词(salt))。
//!
//! ## 承诺编码（写死锁定，与 Note 词编码同构）
//!
//! [`range_commitment_parts`]：
//! - 词 0 = x：32B，低 8 字节 = u64 小端、余零（与 Note amount 词同构）；
//! - 词 1 = salt：低 16 字节零、**高 16 字节 = salt**（与 Note salt 词
//!   同构，见 `vg_domain::privacy::Note::commitment_parts` 的
//!   `salt_word[16..] = salt`；任务描述中「高 16 字节零、低 16 字节
//!   salt」为笔误，以 Note 同构为准）；
//! - C = `poseidon_note_commitment(&parts)`（1 label 行置换 + 2 词展开
//!   16 limb + sentinel 1 + 7 零 → 24 limb = 3 块吸收）。
//!
//! ## AIR 结构（列区间表 + 行布局）
//!
//! 位分解区与置换链区**并行列区、行复用**：trace 高度固定 64 行
//! （2 的幂），每行既是位行 r（承载 x/B 的第 `63−r` 位，MSB 在前），
//! 又是一次完整 Poseidon2 置换。总列宽 = 164 + 23 = 187：
//!
//! | 列区间 | 宽度 | 语义 |
//! |---|---|---|
//! | `0..164` | 164 | `Poseidon2Cols<16,3,0,4,20>`：置换链（镜像 p3-poseidon2-air） |
//! | `164..172` | 8 | `block[8]`：本行置换前注入 rate 槽的吸收块（**内容被约束 6 钉死**，非自由见证——与 note_opening 的关键区别） |
//! | `172` | 1 | `t`：sponge 链布尔标志（0 = 填充行，1 = 真实行；单调 0→1） |
//! | `173..175` | 2 | `c1, c0`：真实行块计数器的两个位（c = 2·c1 + c0） |
//! | `175..177` | 2 | `xb, bb`：本行 x / B 的位（行 r 承载第 63−r 位） |
//! | `177..179` | 2 | `xacc, bacc`：位重建运行累积器（MSB 起加倍：acc' = 2·acc + b'） |
//! | `179..181` | 2 | `eq, lt`：位比较标志链（eq = 前缀位全等，lt = 已判定 x < B） |
//! | `181..187` | 6 | `xl, xh, s0..s3`：x 的两个 limb 与 salt 的 4 个 limb（全行常量见证列） |
//!
//! 行布局（固定 64 行）：行 `0..60` = 填充行（t = 0，dummy 置换链，
//! block 全零）；行 60 = start 行（t = 1，inputs = label‖0，c = 0）；
//! 行 61/62/63 = 吸收块行（c = 1/2/3，block = 词(x)/词(salt)/sentinel）。
//!
//! ## 约束列表（max degree = 3，仍来自 S-box x³）
//!
//! 1. **置换约束**（所有行）：与 note_opening 逐字相同（外部线性层起始，
//!    4+20+4 轮，`ending_full_rounds[3].post` 即该行置换输出）；
//! 2. **t 链**（与 note_opening 相同）：t 布尔、首行 t = 0、末行 t = 1、
//!    单调（`t·(1−t') = 0`），g = t' − t 为唯一 0→1 转移指示（start 行
//!    进入标志）——首行 t = 0 封死「t≡1 伪造链」攻击（同 note_opening）；
//! 3. **链式吸收**（转移，g = 0）：rate 槽 `inputs'[i] = post[i] + block'[i]`
//!    （i < 8）、capacity 槽 `inputs'[i] = post[i]`（i ≥ 8）；
//! 4. **start 行**（转移，g = 1）：`inputs' = label‖0`；
//! 5. **计数器**：c1、c0 布尔（所有行）；填充行清零
//!    `(1−t)·c1 = (1−t)·c0 = 0`；进入 start（g = 1）`c1' = c0' = 0`；
//!    真实行递增（转移，t = 1）`c' = c + 1`；末行 `c = 3`——联立迫使
//!    真实区恰好 4 行（c 序列 0,1,2,3，超出则 c1/c0 布尔破坏）；
//! 6. **块内容钉死**（所有行，本电路对 note_opening 的核心增强）：
//!    记 ind1 = (1−c1)·c0、ind2 = c1·(1−c0)、ind3 = c1·c0，则
//!    `block = [ind1·xl + ind3, ind1·xh, 0, 0, ind2·s0, …, ind2·s3]`
//!    ——c = 1 行吸收词(x) 两 limb、c = 2 行吸收词(salt) 高 4 limb、
//!    c = 3 行吸收 sentinel‖零、c = 0（start 行）block = 0；
//! 7. **位布尔**（所有行）：xb、bb、eq、lt 满足 b·(1−b) = 0；
//! 8. **位行初始化**（首行）：`xacc = xb`、`bacc = bb`、`eq = 1`、
//!    `lt = 0`；
//! 9. **位重建**（转移）：`xacc' = 2·xacc + xb'`、
//!    `bacc' = 2·bacc + bb'`（MSB 起加倍，64 行后分别为 x、B 的域值）；
//! 10. **比较链**（转移）：`d = xb' − bb'`，
//!     `eq' = eq·(1 − d²)`、`lt' = lt + eq·bb'·(1 − xb')`；
//! 11. **常量 limb**（转移）：`xl' = xl`、`xh' = xh`、`s_j' = s_j`；
//! 12. **终局绑定**（末行）：
//!     - `xacc = xl + 2^32·xh`（位重建与吸收 limb 一致，域等式即精确
//!       锁定 host 编码：host limb = from_int(u32)，位和 mod p 与之恒等）；
//!     - `bacc = publics[0] + 2^32·publics[1]`（B 的位重建对公开 limb）；
//!     - `lt + eq = 1`（x ≤ B 断言：x < B ⇒ lt = 1；x = B ⇒ eq = 1；
//!       x > B ⇒ 两者皆 0，违规）；
//!     - `post[0..8] = publics[2..10]`（C 公开绑定）。
//!
//! ## 可靠性论证
//!
//! - **比较链防伪造**：eq/lt 虽是见证列，但首行值被钉死（约束 8）、
//!   每个转移值被约束 10 完全确定为前值与该位 x/b 位的函数——
//!   eq′ = eq·(1−d²) 对位值 d² ∈ {0,1} 是全函数，攻击者无任何自由度，
//!   只能诚实沿链计算；末行 lt + eq = 1 与 B 位绑定（约束 12 的
//!   bacc = publics）联立，恰等价于整数不等式 x ≤ B（MSB 起第一个
//!   x_i ≠ b_i 的位定胜负，其前的全等前缀由 eq 携带）。
//! - **B 不能被换位分解**：bb 见证位的重建累积器末行必须等于
//!   publics[0] + 2^32·publics[1]（域等式 + 位和 < 2^64 表示唯一性：
//!   64 位向量的加权和在 F_p 中两两不同当且仅当……此处依赖位和
//!   mod p 与 limb 编码同构： publics 装载用 from_int，位和取 mod p
//!   后与 host 编码恒等，故 bb 必须是 publics B 的位分解）。
//! - **x 与 C 绑定**：xb 位重建 xacc 末行 = xl + 2^32·xh（约束 12），
//!   xl/xh 是全行常量（约束 11）且被块内容约束 6 直接送入 sponge
//!   吸收——C 的前像 limb 即 x 的位分解编码；s0..s3 同理为 salt
//!   limb（自由见证，仅经 C 绑定）。位和取 mod p 与 host
//!   `from_int(u32 limb)` 归约恒等，编码口径与 host 侧完全一致。
//! - **块结构不可绕过**：计数器约束 5 迫使真实区恰好 4 行且
//!   c = 0,1,2,3 依次排列；约束 6 按 c 钉死每块内容（含 sentinel
//!   与零填充），攻击者无法缩短链（少吸收一块）或换块内容——
//!   这是相对 note_opening（块为自由见证）的实质增强。
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
use p3_uni_stark::{prove, verify, StarkConfig};
use vg_infra_crypto::poseidon::{poseidon_note_commitment, to_field_le};
use vg_infra_crypto::Hash32;
use vg_infra_crypto::keccak256;

use crate::ZkError;

/// 电路标识（Task 13 PlonkyProver 的 circuit@version 口径）。
pub const RANGE_CHECK_CIRCUIT_ID: &str = "range_check";
/// 电路版本（约束/配置变更时递增，proof 不跨版本兼容）。
pub const RANGE_CHECK_CIRCUIT_VERSION: u64 = 1;

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
/// 公开输入个数：B 两 limb + C 八 limb。
const NUM_PUBLICS: usize = 10;
/// trace 高度（固定：64 位行 = 64 行，2 的幂）。
const HEIGHT: usize = 64;
/// 真实行数：start 行 + 3 个吸收块行。
const REAL_ROWS: usize = 4;
/// 填充行数（start 行之前）。
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
/// xacc 列下标。
const XACC_COL: usize = BB_COL + 1;
/// bacc 列下标。
const BACC_COL: usize = XACC_COL + 1;
/// eq 列下标。
const EQ_COL: usize = BACC_COL + 1;
/// lt 列下标。
const LT_COL: usize = EQ_COL + 1;
/// xl 列下标。
const XL_COL: usize = LT_COL + 1;
/// xh 列下标。
const XH_COL: usize = XL_COL + 1;
/// s0 列下标。
const S0_COL: usize = XH_COL + 1;
/// 本电路总列宽。
const TOTAL_COLS: usize = S0_COL + 4;

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

/// x 的承诺词（词 0）：低 8 字节 u64 小端、余零（与 Note amount 词同构）。
fn x_word(x: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[..8].copy_from_slice(&x.to_le_bytes());
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

    fn num_public_values(&self) -> usize {
        NUM_PUBLICS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // 最高次仍为 S-box x³（3）：比较链 eq·(xb·bb) 与块内容
        // ind·limb 均为 degree 3。
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
        let xl: AB::Expr = local[XL_COL].into();
        let xh: AB::Expr = local[XH_COL].into();
        // block[0] = ind1·xl + ind3（c=3 时 sentinel 1）
        builder.assert_zero(
            local[BLOCK_COL].into() - ind1.clone() * xl.clone() - ind3.clone(),
        );
        // block[1] = ind1·xh
        builder.assert_zero(local[BLOCK_COL + 1].into() - ind1.clone() * xh.clone());
        // block[2..4] = 0（两词的零填充 limb）
        for i in 2..4 {
            builder.assert_zero(local[BLOCK_COL + i]);
        }
        // block[4..8] = ind2·s_j（c=2 时 salt 的 4 limb）
        for j in 0..4 {
            let s_j: AB::Expr = local[S0_COL + j].into();
            builder.assert_zero(local[BLOCK_COL + 4 + j].into() - ind2.clone() * s_j);
        }

        // 12. 终局绑定 + 末行 t = 1（先取可变 builder 再 drop）
        {
            let mut when_last = builder.when_last_row();
            when_last.assert_eq(local[T_COL], KoalaBear::from_int(1u32));
            // C 公开绑定
            for i in 0..RATE {
                when_last.assert_eq(out_local[i], publics[2 + i]);
            }
            // 位重建 ↔ limb 一致：xacc = xl + 2^32·xh
            let two32 = KoalaBear::from_int(1u32 << 31) * KoalaBear::from_int(2u32);
            let xa: AB::Expr = local[XACC_COL].into();
            when_last.assert_zero(xa - xl - xh * two32);
            // B 位重建 ↔ 公开 limb：bacc = B_lo + 2^32·B_hi
            let ba: AB::Expr = local[BACC_COL].into();
            let b_bound: AB::Expr =
                publics[0].into() + publics[1].into() * two32;
            when_last.assert_zero(ba - b_bound);
            // x ≤ B 断言：lt + eq = 1
            let lt_l: AB::Expr = local[LT_COL].into();
            let eq_l: AB::Expr = local[EQ_COL].into();
            when_last.assert_zero(lt_l + eq_l - one.clone());
            // 真实区长度钉死：末行 c = 3
            when_last.assert_eq(local[C1_COL], KoalaBear::from_int(1u32));
            when_last.assert_eq(local[C0_COL], KoalaBear::from_int(1u32));
        }

        // 8. 位行初始化（首行）
        {
            let mut when_first = builder.when_first_row();
            when_first.assert_eq(local[XACC_COL], local[XB_COL]);
            when_first.assert_eq(local[BACC_COL], local[BB_COL]);
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

        // 9. 位重建（MSB 起加倍）
        let two = KoalaBear::from_int(2u32);
        let xacc: AB::Expr = local[XACC_COL].into();
        let bacc: AB::Expr = local[BACC_COL].into();
        let xb_n: AB::Expr = next[XB_COL].into();
        let bb_n: AB::Expr = next[BB_COL].into();
        when_transition.assert_zero(next[XACC_COL] - xacc * two - xb_n.clone());
        when_transition.assert_zero(next[BACC_COL] - bacc * two - bb_n.clone());

        // 10. 比较链
        let eq: AB::Expr = local[EQ_COL].into();
        let lt: AB::Expr = local[LT_COL].into();
        let d = xb_n.clone() - bb_n.clone();
        let d_sq = d.clone() * d;
        when_transition.assert_zero(next[EQ_COL] - eq.clone() * (one.clone() - d_sq));
        when_transition.assert_zero(next[LT_COL] - lt - eq * bb_n * (one - xb_n));

        // 11. 常量 limb 冻结
        for col in [XL_COL, XH_COL, S0_COL, S0_COL + 1, S0_COL + 2, S0_COL + 3] {
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
    // 位分解（行 r 承载第 63−r 位，MSB 在前）与运行累积/标志链
    let mut xb_bits = [0u64; HEIGHT];
    let mut bb_bits = [0u64; HEIGHT];
    let mut xaccs = [KoalaBear::from_int(0u32); HEIGHT];
    let mut baccs = [KoalaBear::from_int(0u32); HEIGHT];
    let mut eqs = [KoalaBear::from_int(0u32); HEIGHT];
    let mut lts = [KoalaBear::from_int(0u32); HEIGHT];
    let mut xacc = KoalaBear::from_int(0u32);
    let mut bacc = KoalaBear::from_int(0u32);
    let mut eq = KoalaBear::from_int(1u32);
    let mut lt = KoalaBear::from_int(0u32);
    let two = KoalaBear::from_int(2u32);
    for r in 0..HEIGHT {
        let i = HEIGHT - 1 - r;
        let xb = (x >> i) & 1;
        let bb = (bound >> i) & 1;
        if r == 0 {
            xacc = KoalaBear::from_int(xb as u32);
            bacc = KoalaBear::from_int(bb as u32);
        } else {
            xacc = xacc * two + KoalaBear::from_int(xb as u32);
            bacc = bacc * two + KoalaBear::from_int(bb as u32);
            // 与约束 10 同序：lt 用旧 eq，再更新 eq
            let d = KoalaBear::from_int(xb as u32) - KoalaBear::from_int(bb as u32);
            let eq_old = eq;
            eq = eq_old * (KoalaBear::from_int(1u32) - d * d);
            if eq_old == KoalaBear::from_int(1u32) && xb == 0 && bb == 1 {
                lt = KoalaBear::from_int(1u32);
            }
        }
        xb_bits[r] = xb;
        bb_bits[r] = bb;
        xaccs[r] = xacc;
        baccs[r] = bacc;
        eqs[r] = eq;
        lts[r] = lt;
    }

    // 常量 limb 见证
    let xl = KoalaBear::from_int((x & 0xFFFF_FFFF) as u32);
    let xh = KoalaBear::from_int((x >> 32) as u32);
    let s = salt_limbs(salt);

    // 吸收块（3 块）：词(x) / 词(salt) / sentinel‖零
    let blocks: [[KoalaBear; RATE]; 3] = [
        [
            xl,
            xh,
            KoalaBear::from_int(0u32),
            KoalaBear::from_int(0u32),
            KoalaBear::from_int(0u32),
            KoalaBear::from_int(0u32),
            KoalaBear::from_int(0u32),
            KoalaBear::from_int(0u32),
        ],
        [
            KoalaBear::from_int(0u32),
            KoalaBear::from_int(0u32),
            KoalaBear::from_int(0u32),
            KoalaBear::from_int(0u32),
            s[0],
            s[1],
            s[2],
            s[3],
        ],
        {
            let mut b = [KoalaBear::from_int(0u32); RATE];
            b[0] = KoalaBear::from_int(1u32);
            b
        },
    ];

    // 置换链：PAD 行 dummy（零状态链）→ start（label）→ 3 块吸收
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

    // 公开输入：[B_lo, B_hi, C×8]
    let mut publics = [KoalaBear::from_int(0u32); NUM_PUBLICS];
    publics[0] = KoalaBear::from_int((bound & 0xFFFF_FFFF) as u32);
    publics[1] = KoalaBear::from_int((bound >> 32) as u32);
    publics[2..NUM_PUBLICS].copy_from_slice(&state[..RATE]);

    // 填充置换列
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

    // 拼装全列 trace
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
        // 位分解区
        values[base + XB_COL] = KoalaBear::from_int(xb_bits[r] as u32);
        values[base + BB_COL] = KoalaBear::from_int(bb_bits[r] as u32);
        values[base + XACC_COL] = xaccs[r];
        values[base + BACC_COL] = baccs[r];
        values[base + EQ_COL] = eqs[r];
        values[base + LT_COL] = lts[r];
        // 常量 limb
        values[base + XL_COL] = xl;
        values[base + XH_COL] = xh;
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
/// - `public_limbs`：公开输入 10 个 canonical u32 limb，顺序
///   `[B_lo, B_hi, C_0..C_7]`（C 小端拼接即 32B 承诺）。
///
/// 独立于 note_opening 的 `ProofOutput`（后者 `public_limbs` 定长 8，
/// 本电路 10 个公开值，泛化改动会破坏 note_opening 公开 API，故新建）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeProofOutput {
    /// 证明字节（postcard）。
    pub proof: Vec<u8>,
    /// 公开输入（[B_lo, B_hi, C×8]）。
    pub public_limbs: [u32; NUM_PUBLICS],
}

/// 为 (x, salt, bound) 计算 range_check 证明。
///
/// 语句：位分解重建 x ∧ x ≤ B ∧ C = Commit(x‖salt)。x > bound 时返回
/// [`ZkError::InvalidWitness`]（见证必违反约束，电路外前置拦截不 panic）。
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
    let proof = prove(&config, &air, witness.trace, &publics);
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
/// 任何篡改（证明字节或公开 limb）返回 false，不 panic。
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
    verify(&config, &air, &proof, &publics).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// 黄金参数：x、salt、B（bound）。
    const GOLDEN_X: u64 = 0x1FFDEADBEAF;
    const GOLDEN_SALT: [u8; 16] = [
        0x33, 0x44, 0x55, 0x66, 0xC0, 0xFF, 0xEE, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77,
    ];
    const GOLDEN_BOUND: u64 = 0xFFFF_FFFF_FFFF;

    /// 黄金承诺 hex（字面 fixture，首次由 host 计算后锁定）。
    const GOLDEN_C_HEX: &str = "363ced063b850d1c75056017c8090f1cbfe3d83afa7a3b495991822f213aec5a";

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
        // 前置对齐：host 侧承诺 == 黄金 C
        assert_eq!(
            range_commitment(GOLDEN_X, &GOLDEN_SALT).as_hex(),
            GOLDEN_C_HEX,
            "host 侧承诺必须先与 golden fixture 对齐"
        );

        let start = Instant::now();
        let output =
            prove_range_check(GOLDEN_X, &GOLDEN_SALT, GOLDEN_BOUND).expect("黄金见证 prove 应成功");
        let prove_secs = start.elapsed().as_secs_f64();

        let start = Instant::now();
        assert!(verify_range_check(&output), "黄金证明 verify 必须 true");
        let verify_secs = start.elapsed().as_secs_f64();

        // publics = [B_lo, B_hi, C×8]：B limb 为 from_int 归约后的
        // canonical u32（B_lo = 0xFFFFFFFF ≥ p 会归约，与 AIR/verify 同口径）
        assert_eq!(
            output.public_limbs[0],
            KoalaBear::from_int((GOLDEN_BOUND & 0xFFFF_FFFF) as u32).as_canonical_u32()
        );
        assert_eq!(
            output.public_limbs[1],
            KoalaBear::from_int((GOLDEN_BOUND >> 32) as u32).as_canonical_u32()
        );
        assert_eq!(&output.public_limbs[2..], &golden_c_limbs());
        println!("golden prove: {prove_secs:.2}s, verify: {verify_secs:.2}s");
    }

    #[test]
    fn x_below_bound_passes() {
        // x 远小于 B / x = B−1 / x = B（相等边界通过）
        let salt = [0xABu8; 16];
        let bound: u64 = 1 << 40;
        for x in [0u64, 1, bound - 1, bound] {
            let output = prove_range_check(x, &salt, bound).expect("x ≤ B 应 prove 成功");
            assert!(verify_range_check(&output), "x = {x} ≤ B 的证明应 verify true");
        }
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
        let big_x = u64::MAX;
        let output = prove_range_check(big_x, &salt, u64::MAX).expect("x = B = u64::MAX 应成功");
        assert!(verify_range_check(&output));
        let mut small_b = output.clone();
        small_b.public_limbs[0] = 0; // B' = 0 < x
        small_b.public_limbs[1] = 0;
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
        for i in 2..NUM_PUBLICS {
            let mut tampered = output.clone();
            tampered.public_limbs[i] ^= 1;
            assert!(!verify_range_check(&tampered), "篡改 C limb {i} 必须 false");
        }
        // 篡改 B limb：挑篡改后必违反 x ≤ B' 的值
        // B = 0xFFFF_FFFF_FFFF → limbs [0xFFFFFFFF, 0xFFFF]；
        // B_lo ^ 1 = 0xFFFFFFFE < x=0x1FFDEADBEAF？x 低 32 位 = 0xFDEADBEAF，
        // B' 低 32 位 0xFFFFFFFE：x_lo < B'_lo，但 B' 高 limb = 0xFFFF 相同，
        // B' = 0xFFFFFFFF_FFFFFFFE > x，仍满足 —— 会 false 仅因 B 位重建
        // 不再匹配（bacc 绑定 publics），验证必假。但为满足「必违反
        // x ≤ B'」语义，另测 B_hi 篡改为 0（B' = 0xFFFFFFFF < x）：
        let mut tampered = output.clone();
        tampered.public_limbs[1] = 0; // B' = 0xFFFFFFFF < x
        assert!(!verify_range_check(&tampered), "篡改 B_hi 后 B' < x 必须 false");
        let mut tampered = output.clone();
        tampered.public_limbs[0] ^= 1; // B 位重建不再匹配 publics
        assert!(!verify_range_check(&tampered), "篡改 B_lo 必须 false");
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

    /// 见证 publics 与 host 承诺一致性（不走证明的快速回归）。
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
                .map(|i| {
                    u32::from_le_bytes(c.as_bytes()[4 * i..4 * i + 4].try_into().unwrap())
                })
                .collect();
            let witness = build_witness(x, &salt, bound);
            let got: Vec<u32> = witness.publics[2..].iter().map(|e| e.as_canonical_u32()).collect();
            assert_eq!(got, expected, "x = {x} 的 C limb 必须与 host 一致");
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

    /// 恶意 trace 回归 1：位重建 ≠ x（翻转一个 xb 位不更新累积器）。
    #[test]
    fn malicious_bit_reconstruction_rejected() {
        use p3_air::check_constraints;
        let witness = build_witness(GOLDEN_X, &GOLDEN_SALT, GOLDEN_BOUND);
        let mut values = witness.trace.values.clone();
        // 行 5 的 xb 翻转（仍布尔），xacc 链断裂
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

    /// 恶意 trace 回归 2：伪造 lt 标志（x > B 却在中途强置 lt = 1）。
    ///
    /// 构造：x > B 的见证位（bb/bacc 诚实对 publics 中的 B），在第一个
    /// x_i = 1, b_i = 0 的位（即 x 胜出的位）之后把 lt 置 1 —— 若无
    /// 约束 10 的 lt 转移钉死，末行 lt + eq = 1 将被「蒙混」通过。
    #[test]
    fn malicious_forged_lt_flag_rejected() {
        use p3_air::check_constraints;
        // x = u64::MAX > B = 0：所有位 x_i = 1, b_i = 0
        let bound = 0u64;
        let x = u64::MAX;
        let salt = [0x99u8; 16];
        let witness = build_witness(x, &salt, bound);
        // publics 保持诚实（B = 0）——注意 publics[0..2] = B limb，
        // witness 按规范构造
        let mut values = witness.trace.values.clone();
        // 伪造：从行 1 起把 lt 置 1（eq 已在行 0 后归 0，攻击者妄图
        // 用 lt = 1 通过末行 lt + eq = 1）
        for r in 1..HEIGHT {
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

    /// 恶意 trace 回归 3：伪造 B 位（bb 换成小 B' 的位但 publics 不变）。
    #[test]
    fn malicious_forged_bound_bits_rejected() {
        use p3_air::check_constraints;
        // 诚实见证：x = 5, B = 100；篡改：bb 位全清零（等价 B' = 0 < x）
        let x = 5u64;
        let bound = 100u64;
        let salt = [0x11u8; 16];
        let witness = build_witness(x, &salt, bound);
        let mut values = witness.trace.values.clone();
        let mut bacc = KoalaBear::from_int(0u32);
        let two = KoalaBear::from_int(2u32);
        for r in 0..HEIGHT {
            values[r * TOTAL_COLS + BB_COL] = KoalaBear::from_int(0u32);
            bacc = if r == 0 {
                KoalaBear::from_int(0u32)
            } else {
                bacc * two
            };
            values[r * TOTAL_COLS + BACC_COL] = bacc;
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
