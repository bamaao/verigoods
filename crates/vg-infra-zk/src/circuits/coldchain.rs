//! coldchain_max 电路：证明「知道 8 个私有温度读数的承诺链 root，
//! 且每个读数 t_i ≤ T_max」。
//!
//! ## 语义
//!
//! - **公开输入**（9 个）：`[T_max, root_0..root_7]`——T_max 单 limb
//!   （u32 < 2^30，canonical 装载无失真）；root 的 8 个 limb（小端
//!   拼接即 32B 承诺链根，与 host 侧 [`coldchain_root`] 输出一致）；
//! - **私有见证**：8 个读数 t_i（各 u32 < 2^30，单位建议 centi-degree
//!   （厘度，10^-2 ℃），0..2^30 覆盖 ±10^7 ℃ 量程已宽裕）；
//! - **语句**：root = 8 步链式承诺（每步 `prev' = Commit(prev‖t_i)`，
//!   prev_0 = 32B 零）∧ 每个整数 t_i ≤ T_max（30 位 MSB 前序逐位比较）。
//!
//! 读数 N 固定 8 个（业务侧不足 8 时补零读数 t = 0，host 与电路同
//! 语义——t = 0 是合法读数且恒 ≤ T_max，不改变其它读数的合规性）。
//!
//! ## 编码规范（写死锁定，host 与电路必须一致）
//!
//! [`coldchain_root`]：
//! - prev_0 = 32 字节零；t 词 = 低 4 字节 LE u32、余 28 字节零
//!   （u32 < 2^30 < p 使 `from_int` 恒等装载，无归约歧义）；
//! - `prev_{i+1} = poseidon_note_commitment(&[prev_i 词, t_i 词])`
//!   （每步一个**全新 sponge**：label 初始化 + 2 词 16 limb +
//!   sentinel 1 + 7 零 = 24 limb = 3 块吸收 + squeeze）；
//! - root = prev_8。链中间值 prev_i 的 limb 是 Poseidon2 输出的
//!   canonical 域元素（< p < 2^31），host 侧 word→limb 装载
//!   （`to_field_le`，from_int(u32 < p) 恒等）与电路内直接传递的
//!   域元素严格相等。
//!
//! T_max 的 canonical 性：prove API 拒绝 t_max ≥ 2^30；电路层面
//! B 侧位重建绑定（约束 9）同样封死 T_max ≥ 2^30 的 publics——
//! 30 位累积值 ≤ 2^30 − 1 与装载后的域元素做**域等式**比较，
//! u32 装载值 ∈ [2^30, 2^32) 无法等于任何 < 2^30 的累积值。
//!
//! ## AIR 结构（列区间表 + 行布局）
//!
//! trace 高度固定 512 行（2 的幂）。每个读数占一个 **34 行的读数块**
//! （block j = 行 34j..34j+33）：前 30 行 = 位比较区（t_j 与 T_max 的
//! 30 位 MSB 前序逐位比较），后 4 行 = 该读数的链重算置换组
//! （start + 3 吸收块）。8 块共 272 行，行 272..511 为填充
//! （哑链继续）。总列宽 = 164 + 26 = 190：
//!
//! | 列区间 | 宽度 | 语义 |
//! |---|---|---|
//! | `0..164` | 164 | `Poseidon2Cols<16,3,0,4,20>`：置换链（镜像 p3-poseidon2-air） |
//! | `164..172` | 8 | `block[8]`：吸收块（内容被约束 2 钉死，非自由见证） |
//! | `172..180` | 8 | `pv0..pv7`：本读数块的 prev 词 limb（块内常量见证列，组间由约束 4 链式传递） |
//! | `180` | 1 | `tv`：本读数块的 t_j 值（块内常量见证列，被位区重建绑定） |
//! | `181..183` | 2 | `xb, bb`：本行 t_j / T_max 的比较位 |
//! | `183..185` | 2 | `xa, ba`：位区加倍累积器（30 位无环绕重建） |
//! | `185..187` | 2 | `eq, eqp`：比较标志链 / 其前一行值（eqp 供 win 复用） |
//! | `187..189` | 2 | `db, win`：本行位差平方 / lt 增量项（均为值钉死列） |
//! | `189` | 1 | `lt`：已判定 t_j < T_max 标志 |
//!
//! **预处理列**（9 列，setup 阶段承诺、行结构同源锁定）：`s1, s2, s3`
//! （本行是读数块内第 1/2/3 个吸收块行）、`zb`（位比较区行）、
//! `zstart / zend`（位区首/末行）、`bend`（读数块末行）、`start`
//! （链重算组 start 行）、`final`（行 271 = 末块末行）。行布局由
//! 预处理列**完全钉死**，杜绝见证自选区/块边界的攻击面。
//!
//! ## 约束列表（max degree = 3，最高次来自 S-box x³ / win 项）
//!
//! 1. **置换约束**（所有行）：与 note_opening / range_check 逐字同构；
//! 2. **块内容钉死**（所有行，degree 2）：
//!    `block[0] = s1·pv_0 + s2·tv + s3`、`block[i] = s1·pv_i`（i ≥ 1）
//!    ——组内 c = 1 行吸收 prev 词 8 limb、c = 2 行吸收 [t_j, 0…, 0]、
//!    c = 3 行吸收 sentinel‖零、其余行 block = 0；
//! 3. **块内常量**（转移，degree 2）：`(1−bend)·(pv_i' − pv_i) = 0`、
//!    `(1−bend)·(tv' − tv) = 0`——pv / tv 仅在读数块边界可变；
//! 4. **组间 prev 传递**（转移 + 首行）：`bend·(pv_i' − post_i) = 0`
//!    （下一块的 prev = 本块链重算输出）；首行 `pv_i = 0`
//!    （prev_0 = 32B 零，递推锚点）；
//! 5. **布尔与值钉死**（所有行）：xb/bb/eq/lt 布尔；
//!    `db = (xb − bb)²`、`win = eqp·bb·(1 − xb)`（值列，degree ≤ 3）；
//! 6. **位区外位值相等**（所有行，degree 2）：`(1−zb)·(xb − bb) = 0`
//!    ——位区外 d = 0 使比较链自动冻结；
//! 7. **累积器**（转移）：`cont·(a' − 2a − b') = 0`、
//!    `zstart'·(a' − b') = 0`，其中 `cont = zb·zb'`（degree 3）——
//!    区内 MSB 起加倍、区首复位为位值；
//! 8. **比较链**（转移，degree ≤ 3）：zstart 转移置
//!    `eq' = eqp' = 1`、`lt' = 0`（每读数块比较重新开始）；其余转移
//!    `eq' = eq·(1 − db')`、`eqp' = eq`、`lt' = lt + win'`；
//! 9. **绑定与终局**（local，预处理指示子定位）：每个 zend 行
//!    `xa = tv`、`ba = publics[0]`（T_max 位重建绑定）、
//!    `lt + eq = 1`（t_j < T_max ⇒ lt = 1、t_j = T_max ⇒ eq = 1、
//!    t_j > T_max ⇒ 两者皆 0 违规）；`final` 行
//!    `post[0..8] = publics[1..9]`（root 公开绑定）；
//! 10. **首行初始化**：`eq = eqp = 1`、`lt = 0`、`xa = xb`、`ba = bb`
//!     （行 0 即块 0 位区首行）。
//!
//! ## 可靠性论证（soundness）
//!
//! - **无环绕**：位区恰 30 行（预处理钉死），累积器从区首复位值
//!   （= 位值）经确定性递推 `a' = 2a + b'` 逐步累积，归纳可得任意
//!   中间值 ≤ 2^30 − 1 < p（KoalaBear p = 0x7F000001 > 2^30），
//!   域运算与整数运算一致——zend 绑定 `xa = tv`、`ba = publics[0]`
//!   是整数等式：tv 被其 30 位分解唯一确定（恒 < 2^30），bb 位被
//!   迫为整数 T_max 的 30 位 MSB 分解。
//! - **组间 prev 传递不可伪造**：块 j 的 pv 列在块内冻结（约束 3）、
//!   在块边界被 `bend·(pv' = post)` 钉为本块链重算输出（约束 4），
//!   块 0 的 pv 由首行清零锚定——归纳可得块 j 的 c = 1 吸收块恒为
//!   root_j 的 8 个 canonical limb，与 host 链逐字一致。
//! - **块结构不可绕过**：块内 4 行的角色（start / c1 / c2 / c3）由
//!   预处理 s1/s2/s3/start 列钉死；start 行输入被钉为 label‖零
//!   （每读数块全新 sponge，与 host 规范一致）；吸收块内容按约束 2
//!   钉死（prev 词 / [t_j, 0…] / sentinel‖零），无自由块。
//! - **比较链防伪造**：eq/lt 虽是见证列，但区首被钉死（约束 8）、
//!   每个转移值被完全确定为前值与位值的函数（零自由度）；位区外
//!   xb = bb（约束 6）使 db = 0、win = 0，链自动冻结；zend 终局
//!   `lt + eq = 1` 与 30 位 MSB 前序联立恰等价整数不等式
//!   t_j ≤ T_max。比较从不对位加权和求域和，无 mod-p 介入。
//! - **行数与布局**：全部区/块边界由预处理列锁定，final 行唯一，
//!   root 公开绑定只在 final 行生效——填充区（行 272..511）无任何
//!   指示子，只能以哑链续接，无法伪造第二条链。
//!
//! ## 诚实边界
//!
//! 非零知识（crate 根文档）：proof 泄露 witness openings；t_i 序列
//! 可从 proof 复原，T_max/root 本就公开。Phase 3 盲化改造前不用于
//! 上链隐私场景。

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

/// 电路标识（ProverDispatcher 的 circuit@version 口径）。
pub const COLDCHAIN_MAX_CIRCUIT_ID: &str = "coldchain_max";
/// 电路版本（约束/配置变更时递增，proof 不跨版本兼容）。
pub const COLDCHAIN_MAX_CIRCUIT_VERSION: u64 = 1;

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
/// 读数个数（固定 8，业务侧不足补零读数）。
const NUM_READINGS: usize = 8;
/// 每读数比较位数（无环绕基石：2^30 < p = 0x7F000001）。
const CHUNK_BITS: u32 = 30;
/// 每读数块行数：30 位比较行 + 4 行链重算置换组。
const BLOCK_ROWS: usize = CHUNK_BITS as usize + 4;
/// 链区总行数（8 块 × 34）。
const CHAIN_ROWS: usize = NUM_READINGS * BLOCK_ROWS;
/// trace 高度（2 的幂：272 链行 + 240 填充行）。
const HEIGHT: usize = 512;
/// log2(HEIGHT)。
const HEIGHT_LOG: usize = 9;
/// 公开输入个数：T_max + root 8 limb。
const NUM_PUBLICS: usize = 9;
/// 读数 / T_max 的共同上限（2^30，无环绕编码边界）。
const MAX_VALUE: u32 = 1 << 30;

/// 置换列区宽度（p3-poseidon2-air 同款列布局的 `num_cols`）。
const PERM_COLS: usize =
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
/// block[8] 起始下标。
const BLOCK_COL: usize = PERM_COLS;
/// pv0（本块 prev 词 limb）列下标。
const PV0_COL: usize = BLOCK_COL + RATE;
/// tv（本块读数值）列下标。
const TV_COL: usize = PV0_COL + RATE;
/// xb 列下标。
const XB_COL: usize = TV_COL + 1;
/// bb 列下标。
const BB_COL: usize = XB_COL + 1;
/// xa 列下标。
const XA_COL: usize = BB_COL + 1;
/// ba 列下标。
const BA_COL: usize = XA_COL + 1;
/// eq 列下标。
const EQ_COL: usize = BA_COL + 1;
/// eqp（前一行 eq）列下标。
const EQP_COL: usize = EQ_COL + 1;
/// db（位差平方）列下标。
const DB_COL: usize = EQP_COL + 1;
/// win（lt 增量项）列下标。
const WIN_COL: usize = DB_COL + 1;
/// lt 列下标。
const LT_COL: usize = WIN_COL + 1;
/// 本电路总列宽。
const TOTAL_COLS: usize = LT_COL + 1;

// 预处理列下标（语义见模块文档）。
/// s1：本行是块内第 1 个吸收块行（c = 1）。
const PP_S1: usize = 0;
/// s2：c = 2 行。
const PP_S2: usize = 1;
/// s3：c = 3 行。
const PP_S3: usize = 2;
/// zb：位比较区行。
const PP_ZB: usize = 3;
/// zstart：位区首行。
const PP_ZSTART: usize = 4;
/// zend：位区末行。
const PP_ZEND: usize = 5;
/// bend：读数块末行。
const PP_BEND: usize = 6;
/// start：链重算组 start 行。
const PP_START: usize = 7;
/// final：末块末行（root 公开绑定行）。
const PP_FINAL: usize = 8;
/// 预处理列总数。
const PP_COLS: usize = PP_FINAL + 1;

// ---- StarkConfig 组装（与 note_opening / range_check 同款 two-adic 配置） ----

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
type ColdchainConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// 组装 STARK 配置（确定性，参数与既有电路一致）。
fn coldchain_config() -> ColdchainConfig {
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
    ColdchainConfig::new(pcs, challenger)
}

/// 域分隔 label 的 8 个 limb（与 host 侧 sponge 第 1 步一致）。
fn label_limbs() -> [KoalaBear; RATE] {
    let digest = keccak256(DOMAIN_LABEL);
    let limbs = to_field_le(&digest);
    let mut out = [KoalaBear::from_int(0u32); RATE];
    out.copy_from_slice(&limbs);
    out
}

/// 读数 t 的承诺词：低 4 字节 LE u32、余 28 字节零。
fn t_word(t: u32) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[..4].copy_from_slice(&t.to_le_bytes());
    w
}

/// host 侧冷链承诺链根（编码规范见模块文档，golden 字面锁定）：
/// `prev_0 = 0`，`prev_{i+1} = Commit(prev_i ‖ t_i)`，root = prev_8。
pub fn coldchain_root(readings: &[u32; NUM_READINGS]) -> Hash32 {
    let mut prev = [0u8; 32];
    for &t in readings {
        let parts = [prev, t_word(t)];
        prev = *poseidon_note_commitment(&parts).as_bytes();
    }
    Hash32::from_bytes(prev)
}

/// AIR：coldchain_max（结构见模块文档）。
#[derive(Debug, Clone)]
pub struct ColdchainAir {
    /// 置换轮常数（与 `default_koalabear_poseidon2_16` 同源）。
    constants: RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    /// 域分隔 label limb。
    label: [KoalaBear; RATE],
}

impl ColdchainAir {
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

    /// 预处理 trace（列 `[s1, s2, s3, zb, zstart, zend, bend, start, final]`，
    /// 行布局见模块文档）。
    fn build_preprocessed(&self) -> RowMajorMatrix<KoalaBear> {
        let mut values = vec![KoalaBear::from_int(0u32); HEIGHT * PP_COLS];
        for r in 0..HEIGHT {
            let real = r < CHAIN_ROWS;
            let m = r % BLOCK_ROWS;
            let ind = |b: bool| KoalaBear::from_int(u32::from(b));
            let base = r * PP_COLS;
            values[base + PP_S1] = ind(real && m == CHUNK_BITS as usize + 1);
            values[base + PP_S2] = ind(real && m == CHUNK_BITS as usize + 2);
            values[base + PP_S3] = ind(real && m == CHUNK_BITS as usize + 3);
            values[base + PP_ZB] = ind(real && m < CHUNK_BITS as usize);
            values[base + PP_ZSTART] = ind(real && m == 0);
            values[base + PP_ZEND] = ind(real && m == CHUNK_BITS as usize - 1);
            values[base + PP_BEND] = ind(real && m == BLOCK_ROWS - 1);
            values[base + PP_START] = ind(real && m == CHUNK_BITS as usize);
            values[base + PP_FINAL] = ind(r == CHAIN_ROWS - 1);
        }
        RowMajorMatrix::new(values, PP_COLS)
    }
}

impl Default for ColdchainAir {
    fn default() -> Self {
        Self::new()
    }
}

impl BaseAir<KoalaBear> for ColdchainAir {
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
        // 最高次为 S-box x³ / win = eqp·bb·(1−xb)（均 3）；累积器 cont
        // 守卫乘积为 degree 3（zb/cont 是预处理常量）。
        Some(3)
    }
}

impl<AB> Air<AB> for ColdchainAir
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
        let s1: AB::Expr = prep_local[PP_S1].into();
        let s2: AB::Expr = prep_local[PP_S2].into();
        let s3: AB::Expr = prep_local[PP_S3].into();
        let zb: AB::Expr = prep_local[PP_ZB].into();
        let zend: AB::Expr = prep_local[PP_ZEND].into();
        let bend: AB::Expr = prep_local[PP_BEND].into();

        // 2. 块内容钉死（所有行）：c=1 行吸收 prev 词、c=2 行吸收
        // [t_j, 0…]、c=3 行吸收 sentinel‖零、其余行 block = 0
        builder.assert_zero(
            local[BLOCK_COL].into()
                - s1.clone() * local[PV0_COL].into()
                - s2.clone() * local[TV_COL].into()
                - s3.clone(),
        );
        for i in 1..RATE {
            builder
                .assert_zero(local[BLOCK_COL + i].into() - s1.clone() * local[PV0_COL + i].into());
        }

        // 5. 布尔与值钉死（所有行）
        for col in [XB_COL, BB_COL, EQ_COL, LT_COL] {
            let b: AB::Expr = local[col].into();
            builder.assert_zero(b.clone() * (b - one.clone()));
        }
        let xb: AB::Expr = local[XB_COL].into();
        let bb: AB::Expr = local[BB_COL].into();
        let d = xb.clone() - bb.clone();
        builder.assert_zero(local[DB_COL].into() - d.clone() * d);
        builder.assert_zero(
            local[WIN_COL].into() - local[EQP_COL].into() * bb.clone() * (one.clone() - xb.clone()),
        );

        // 6. 位区外位值冻结为相等（xb = bb）：比较链在位区外自动冻结
        builder.assert_zero((one.clone() - zb.clone()) * (xb.clone() - bb.clone()));

        // 9. zend 绑定与终局（每个读数块位区末行）
        builder.assert_zero(zend.clone() * (local[XA_COL].into() - local[TV_COL].into()));
        builder.assert_zero(zend.clone() * (local[BA_COL].into() - publics[0].into()));
        builder.assert_zero(
            zend.clone() * (local[LT_COL].into() + local[EQ_COL].into() - one.clone()),
        );

        // 9b. final 行 root 公开绑定
        for i in 0..RATE {
            builder.assert_zero(
                prep_local[PP_FINAL].into() * (out_local[i].into() - publics[1 + i].into()),
            );
        }

        // 10. 首行初始化（行 0 = 块 0 位区首行）
        {
            let mut when_first = builder.when_first_row();
            when_first.assert_eq(local[EQ_COL], KoalaBear::from_int(1u32));
            when_first.assert_eq(local[EQP_COL], KoalaBear::from_int(1u32));
            when_first.assert_zero(local[LT_COL]);
            when_first.assert_eq(local[XA_COL], local[XB_COL]);
            when_first.assert_eq(local[BA_COL], local[BB_COL]);
            // 4b. prev_0 = 32B 零（递推锚点）
            for i in 0..RATE {
                when_first.assert_zero(local[PV0_COL + i]);
            }
        }

        // ---- 转移约束 ----
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

        let zstart_n: AB::Expr = prep_next[PP_ZSTART].into();
        let start_n: AB::Expr = prep_next[PP_START].into();
        let zb_n: AB::Expr = prep_next[PP_ZB].into();
        let one_minus_zstart_n = one.clone() - zstart_n.clone();
        let one_minus_start_n = one.clone() - start_n.clone();

        let mut when_transition = builder.when_transition();

        // 链式吸收（非 start 进入，g 守卫换为预处理 start' 指示）
        for i in 0..RATE {
            let chain = inputs_next[i].into() - out_local[i].into() - next[BLOCK_COL + i].into();
            when_transition.assert_zero(one_minus_start_n.clone() * chain);
        }
        for i in RATE..WIDTH {
            when_transition.assert_zero(
                one_minus_start_n.clone() * (inputs_next[i].into() - out_local[i].into()),
            );
        }
        // start 行进入：inputs' = label‖零（每读数块全新 sponge）
        for (input_next, label_i) in inputs_next.iter().zip(self.label) {
            when_transition.assert_zero(start_n.clone() * (*input_next - label_i));
        }
        for input_next in inputs_next.iter().take(WIDTH).skip(RATE) {
            when_transition.assert_zero(start_n.clone() * *input_next);
        }

        // 3. 块内常量：pv / tv 仅在读数块边界（bend 转移）可变
        for i in 0..RATE {
            when_transition.assert_zero(
                (one.clone() - bend.clone())
                    * (next[PV0_COL + i].into() - local[PV0_COL + i].into()),
            );
        }
        when_transition.assert_zero(
            (one.clone() - bend.clone()) * (next[TV_COL].into() - local[TV_COL].into()),
        );

        // 4. 组间 prev 传递：下一块的 pv = 本块（bend 行）置换输出
        for i in 0..RATE {
            when_transition
                .assert_zero(bend.clone() * (next[PV0_COL + i].into() - out_local[i].into()));
        }

        // 7. 累积器：区内加倍（cont = zb·zb'）、区首复位为位值
        let two = KoalaBear::from_int(2u32);
        let cont = zb.clone() * zb_n.clone();
        for (acc, bit) in [(XA_COL, XB_COL), (BA_COL, BB_COL)] {
            let a: AB::Expr = local[acc].into();
            let a_n: AB::Expr = next[acc].into();
            let b_n: AB::Expr = next[bit].into();
            when_transition.assert_zero(cont.clone() * (a_n.clone() - a * two - b_n.clone()));
            when_transition.assert_zero(zstart_n.clone() * (a_n - b_n));
        }

        // 8. 比较链：zstart 转移重置（每读数块重新比较），其余转移推进
        let eq: AB::Expr = local[EQ_COL].into();
        when_transition.assert_zero(
            one_minus_zstart_n.clone()
                * (next[EQ_COL].into() - eq.clone() + eq.clone() * next[DB_COL].into()),
        );
        when_transition.assert_zero(zstart_n.clone() * (next[EQ_COL].into() - one.clone()));
        when_transition
            .assert_zero(one_minus_zstart_n.clone() * (next[EQP_COL].into() - eq.clone()));
        when_transition.assert_zero(zstart_n.clone() * (next[EQP_COL].into() - one.clone()));
        when_transition.assert_zero(
            one_minus_zstart_n.clone()
                * (next[LT_COL].into() - local[LT_COL].into() - next[WIN_COL].into()),
        );
        when_transition.assert_zero(zstart_n.clone() * next[LT_COL]);
    }
}

/// 按行重算一次完整 Poseidon2 置换（与既有电路逐字同构）。
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
fn build_witness(readings: &[u32; NUM_READINGS], t_max: u32) -> Witness {
    let one_f = KoalaBear::from_int(1u32);
    let zero_f = KoalaBear::from_int(0u32);
    let two = KoalaBear::from_int(2u32);

    // ---- host 链：prev 词序列（块 j 吸收 prev_j；root = prev_8） ----
    let mut prev_words = [[0u8; 32]; NUM_READINGS];
    let mut pw = [0u8; 32];
    for (j, &t) in readings.iter().enumerate() {
        prev_words[j] = pw;
        let parts = [pw, t_word(t)];
        pw = *poseidon_note_commitment(&parts).as_bytes();
    }
    let root = pw;

    // ---- 位区数据（每块 30 行，MSB 前序） ----
    // 每行 7 元组 (xb, bb, xa, ba, eq, eqp, lt) 的诚实计算
    let mut bit_rows: Vec<[KoalaBear; 7]> = Vec::with_capacity(CHAIN_ROWS);
    for &t in readings {
        let mut xa = zero_f;
        let mut ba = zero_f;
        let mut eq = one_f;
        let mut lt = zero_f;
        for k in 0..CHUNK_BITS as usize {
            let i = CHUNK_BITS - 1 - k as u32; // MSB 在前
            let xb = (t >> i) & 1;
            let bb = (t_max >> i) & 1;
            let eqp = if k == 0 { one_f } else { eq };
            let db = if xb == bb { zero_f } else { one_f };
            let win = if eqp == one_f && xb == 0 && bb == 1 {
                one_f
            } else {
                zero_f
            };
            // 区首复位（约束 8/10），区内按链推进
            eq = if k == 0 { one_f } else { eq * (one_f - db) };
            lt = if k == 0 { zero_f } else { lt + win };
            if k == 0 {
                xa = KoalaBear::from_int(xb);
                ba = KoalaBear::from_int(bb);
            } else {
                xa = xa * two + KoalaBear::from_int(xb);
                ba = ba * two + KoalaBear::from_int(bb);
            }
            bit_rows.push([
                KoalaBear::from_int(xb),
                KoalaBear::from_int(bb),
                xa,
                ba,
                eq,
                eqp,
                lt,
            ]);
        }
    }

    // ---- 置换链：块 j 的 4 行（start / c1 / c2 / c3），块间与填充哑链续接 ----
    let perm_host = default_koalabear_poseidon2_16();
    let label = label_limbs();

    let mut inputs: Vec<[KoalaBear; WIDTH]> = Vec::with_capacity(HEIGHT);
    let mut state = [zero_f; WIDTH];
    let mut final_state = [zero_f; WIDTH];
    for r in 0..HEIGHT {
        let real = r < CHAIN_ROWS;
        let m = r % BLOCK_ROWS;
        let j = r / BLOCK_ROWS;
        if real && m == CHUNK_BITS as usize {
            // start 行：全新 sponge，state = label‖零
            let mut s = [zero_f; WIDTH];
            s[..RATE].copy_from_slice(&label);
            state = s;
        } else if real && m == CHUNK_BITS as usize + 1 {
            // c=1：吸收 prev 词 8 limb
            let pv = to_field_le(&prev_words[j]);
            for i in 0..RATE {
                state[i] += pv[i];
            }
        } else if real && m == CHUNK_BITS as usize + 2 {
            // c=2：吸收 t 词（limb0 = t_j，余零）
            state[0] += KoalaBear::from_int(readings[j]);
        } else if real && m == CHUNK_BITS as usize + 3 {
            // c=3：吸收 sentinel‖零
            state[0] += one_f;
        }
        // 其余行（位区 / 填充）：哑链续接（block = 0），state 不变
        inputs.push(state);
        perm_host.permute_mut(&mut state);
        if r == CHAIN_ROWS - 1 {
            final_state = state;
        }
    }

    // ---- 公开输入：[T_max, root×8]（与 host 链对账） ----
    let root_limbs = to_field_le(&root);
    debug_assert_eq!(
        root_limbs
            .iter()
            .zip(final_state[..RATE].iter())
            .filter(|(a, b)| a != b)
            .count(),
        0,
        "电路链输出必须与 host coldchain_root 一致"
    );
    let mut publics = [zero_f; NUM_PUBLICS];
    publics[0] = KoalaBear::from_int(t_max);
    publics[1..NUM_PUBLICS].copy_from_slice(&root_limbs);

    // ---- 填充置换列并拼装全列 trace ----
    let air = ColdchainAir::new();
    let perm_matrix = generate_trace_rows::<
        KoalaBear,
        GenericPoseidon2LinearLayersKoalaBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, &air.constants, 0);

    let mut values = vec![zero_f; HEIGHT * TOTAL_COLS];
    let mut bit_cursor = 0usize;
    for r in 0..HEIGHT {
        let base = r * TOTAL_COLS;
        let src = &perm_matrix.values[r * PERM_COLS..(r + 1) * PERM_COLS];
        values[base..base + PERM_COLS].copy_from_slice(src);
        let real = r < CHAIN_ROWS;
        let m = r % BLOCK_ROWS;
        let j = r / BLOCK_ROWS;
        // block 列：c=1 行 prev 词、c=2 行 [t,0…]、c=3 行 sentinel‖零
        if real && m == CHUNK_BITS as usize + 1 {
            let pv = to_field_le(&prev_words[j]);
            values[base + BLOCK_COL..base + BLOCK_COL + RATE].copy_from_slice(&pv);
        } else if real && m == CHUNK_BITS as usize + 2 {
            values[base + BLOCK_COL] = KoalaBear::from_int(readings[j]);
        } else if real && m == CHUNK_BITS as usize + 3 {
            values[base + BLOCK_COL] = one_f;
        }
        // pv / tv：块内常量；填充行 pv 冻结为 root（末块 bend 转移的
        // `bend·(pv' = post)` 钉死）、tv 冻结为末块读数
        let pv_source = if real { &prev_words[j] } else { &root };
        let pv = to_field_le(pv_source);
        values[base + PV0_COL..base + PV0_COL + RATE].copy_from_slice(&pv);
        values[base + TV_COL] = KoalaBear::from_int(readings[j.min(NUM_READINGS - 1)]);
        // 位区列：位 / 累积器 / 比较链；非位行冻结（xb=bb=0、累积器 0、
        // eq/eqp/lt 携带末个位区终值——约束 6/8 的位区外冻结要求）
        let mut row = [zero_f; 7];
        if real && m < CHUNK_BITS as usize {
            row = bit_rows[bit_cursor];
            bit_cursor += 1;
        } else if bit_cursor > 0 {
            row = bit_rows[bit_cursor - 1];
            // 非位行：位与累积器清零，eq/eqp/lt 冻结
            row[0] = zero_f;
            row[1] = zero_f;
            row[2] = zero_f;
            row[3] = zero_f;
        }
        values[base + XB_COL] = row[0];
        values[base + BB_COL] = row[1];
        values[base + XA_COL] = row[2];
        values[base + BA_COL] = row[3];
        values[base + EQ_COL] = row[4];
        values[base + EQP_COL] = row[5];
        values[base + LT_COL] = row[6];
        // db / win：按值钉死公式直接计算
        let d = row[0] - row[1];
        values[base + DB_COL] = d * d;
        values[base + WIN_COL] = row[5] * row[1] * (one_f - row[0]);
    }

    Witness {
        trace: RowMajorMatrix::new(values, TOTAL_COLS),
        publics,
    }
}

/// coldchain_max 证明输出。
///
/// - `proof`：postcard 序列化的 `p3_uni_stark::Proof<ColdchainConfig>`
///   字节（配置随 [`COLDCHAIN_MAX_CIRCUIT_VERSION`] 锁定）；
/// - `public_limbs`：公开输入 9 个 canonical u32 limb，顺序
///   `[T_max, root_0..root_7]`（T_max 恒 < 2^30；root 小端拼接即 32B
///   承诺链根）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColdchainProofOutput {
    /// 证明字节（postcard）。
    pub proof: Vec<u8>,
    /// 公开输入（[T_max, root×8]）。
    pub public_limbs: [u32; NUM_PUBLICS],
}

/// 为 (readings, t_max) 计算 coldchain_max 证明。
///
/// 语句：root = 8 步链式承诺 ∧ 每个整数 t_i ≤ T_max。任一读数
/// ≥ 2^30、t_max ≥ 2^30 或存在 t_i > t_max（语句为假）时返回
/// [`ZkError::InvalidWitness`]（电路外前置拦截，不 panic）。
pub fn prove_coldchain(
    readings: &[u32; NUM_READINGS],
    t_max: u32,
) -> Result<ColdchainProofOutput, ZkError> {
    if t_max >= MAX_VALUE {
        return Err(ZkError::InvalidWitness(format!(
            "t_max ({t_max}) 必须 < 2^30（canonical 单 limb 编码边界）"
        )));
    }
    for (i, &t) in readings.iter().enumerate() {
        if t >= MAX_VALUE {
            return Err(ZkError::InvalidWitness(format!(
                "读数 t_{i} ({t}) 必须 < 2^30（centi-degree 编码边界）"
            )));
        }
        if t > t_max {
            return Err(ZkError::InvalidWitness(format!(
                "读数 t_{i} ({t}) 超过上限 t_max ({t_max})，语句为假"
            )));
        }
    }
    let witness = build_witness(readings, t_max);
    let config = coldchain_config();
    let air = ColdchainAir::new();
    let publics: Vec<KoalaBear> = witness.publics.to_vec();
    let (pp, _vk) = setup_preprocessed(&config, &air, HEIGHT_LOG)
        .expect("本 AIR 定义 9 列预处理列，setup 应返回 Some");
    let proof = prove_with_preprocessed(&config, &air, witness.trace, &publics, Some(&pp));
    let bytes = postcard::to_allocvec(&proof).map_err(|e| ZkError::Serialization(e.to_string()))?;
    let mut public_limbs = [0u32; NUM_PUBLICS];
    for (i, v) in witness.publics.iter().enumerate() {
        public_limbs[i] = v.as_canonical_u32();
    }
    Ok(ColdchainProofOutput {
        proof: bytes,
        public_limbs,
    })
}

/// 验证 coldchain_max 证明（publics 取 `output.public_limbs`）。
///
/// 任何篡改（证明字节或公开 limb）返回 false，不 panic。预处理列的
/// verifier key 由 `setup_preprocessed` 确定性重建并经 `OnceLock`
/// 缓存（AIR/config 全确定性，跨调用不变）。
pub fn verify_coldchain(output: &ColdchainProofOutput) -> bool {
    let Ok(proof) = postcard::from_bytes(&output.proof) else {
        return false;
    };
    let publics: Vec<KoalaBear> = output
        .public_limbs
        .iter()
        .map(|l| KoalaBear::from_int(*l))
        .collect();
    let config = coldchain_config();
    let air = ColdchainAir::new();
    verify_with_preprocessed(&config, &air, &proof, &publics, Some(coldchain_vk())).is_ok()
}

/// 预处理 verifier key 的进程级缓存（AIR/config 全确定性）。
fn coldchain_vk() -> &'static p3_uni_stark::PreprocessedVerifierKey<ColdchainConfig> {
    static VK: std::sync::OnceLock<p3_uni_stark::PreprocessedVerifierKey<ColdchainConfig>> =
        std::sync::OnceLock::new();
    VK.get_or_init(|| {
        let config = coldchain_config();
        let air = ColdchainAir::new();
        setup_preprocessed(&config, &air, HEIGHT_LOG)
            .expect("本 AIR 定义 9 列预处理列，setup 应返回 Some")
            .1
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// 黄金读数（centi-degree：23.50℃ … 24.20℃）与上限 25.00℃。
    const GOLDEN_READINGS: [u32; NUM_READINGS] = [2350, 2400, 2380, 2415, 2390, 2365, 2420, 2375];
    const GOLDEN_T_MAX: u32 = 2500;

    /// 黄金链根 hex（字面 fixture，首次由 host 计算后锁定）。
    const GOLDEN_ROOT_HEX: &str =
        "27ab2150f1383e57968fee51efda4c4194075d4bcbfc483973db3f66180cdb18";

    /// 黄金 root 的 8 个 u32 小端 limb。
    fn golden_root_limbs() -> [u32; 8] {
        let bytes = hex::decode(GOLDEN_ROOT_HEX).unwrap();
        (0..8)
            .map(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    #[test]
    fn golden_coldchain_proves_and_verifies() {
        // 无环绕前提自检：2^30 < p
        const P: u64 = 0x7F00_0001;
        const _: () = assert!(1u64 << 30 < P, "无环绕原则要求 2^30 < p");

        // 前置对齐：host 侧链根 == 黄金 root
        assert_eq!(
            coldchain_root(&GOLDEN_READINGS).as_hex(),
            GOLDEN_ROOT_HEX,
            "host 侧链根必须先与 golden fixture 对齐"
        );

        let start = Instant::now();
        let output =
            prove_coldchain(&GOLDEN_READINGS, GOLDEN_T_MAX).expect("黄金见证 prove 应成功");
        let prove_secs = start.elapsed().as_secs_f64();

        let start = Instant::now();
        assert!(verify_coldchain(&output), "黄金证明 verify 必须 true");
        let verify_secs = start.elapsed().as_secs_f64();

        // publics = [T_max, root×8]
        assert_eq!(output.public_limbs[0], GOLDEN_T_MAX);
        assert_eq!(&output.public_limbs[1..], &golden_root_limbs());
        // proof 体积哨兵（上链/存储口径参考）
        println!("golden proof size: {} bytes", output.proof.len());
        assert!(
            output.proof.len() < 200_000,
            "proof 体积 {} 超过上链/存储参考上限 200KB",
            output.proof.len()
        );
        println!("golden prove: {prove_secs:.2}s, verify: {verify_secs:.2}s");
    }

    #[test]
    fn compliant_sequences_pass() {
        // 全 0 读数 / 全部 t = T_max 边界 / 混合边界
        for (readings, t_max) in [
            ([0u32; NUM_READINGS], 0u32),
            ([2500u32; NUM_READINGS], 2500),
            ([0, 1, 2499, 2500, 1250, 2500, 0, 2499], 2500),
        ] {
            let output = prove_coldchain(&readings, t_max)
                .unwrap_or_else(|e| panic!("合规序列应 prove 成功：{e}"));
            assert!(verify_coldchain(&output), "合规序列证明应 verify true");
            assert_eq!(output.public_limbs[0], t_max);
            // host 对账
            let root = coldchain_root(&readings);
            let expected: Vec<u32> = (0..8)
                .map(|i| u32::from_le_bytes(root.as_bytes()[4 * i..4 * i + 4].try_into().unwrap()))
                .collect();
            assert_eq!(&output.public_limbs[1..], &expected[..]);
        }
    }

    #[test]
    fn violating_sequences_rejected() {
        // 某读数 > T_max：prove 前置拦截（不 panic）
        let readings = [2350, 2400, 2501, 2415, 2390, 2365, 2420, 2375];
        let err =
            prove_coldchain(&readings, 2500).expect_err("t_2 = 2501 > t_max = 2500 必须被拒绝");
        assert!(matches!(err, ZkError::InvalidWitness(_)));
        // 编码边界：t_max ≥ 2^30、读数 ≥ 2^30
        let err = prove_coldchain(&GOLDEN_READINGS, 1 << 30).expect_err("t_max ≥ 2^30 必须被拒绝");
        assert!(matches!(err, ZkError::InvalidWitness(_)));
        let mut bad = GOLDEN_READINGS;
        bad[7] = 1 << 30;
        let err = prove_coldchain(&bad, (1 << 30) - 1).expect_err("读数 ≥ 2^30 必须被拒绝");
        assert!(matches!(err, ZkError::InvalidWitness(_)));
    }

    #[test]
    fn tampered_publics_fail() {
        let output = prove_coldchain(&GOLDEN_READINGS, GOLDEN_T_MAX).unwrap();
        assert!(verify_coldchain(&output));
        // 篡改 T_max（更小使某读数越界）→ false
        let mut tampered = output.clone();
        tampered.public_limbs[0] = 2400; // t_1 = 2400 ≤、t_3 = 2415 > 2400
        assert!(
            !verify_coldchain(&tampered),
            "缩小 T_max 使读数越界必须 false"
        );
        // 篡改 root 任一 limb → false
        for i in 1..NUM_PUBLICS {
            let mut tampered = output.clone();
            tampered.public_limbs[i] ^= 1;
            assert!(
                !verify_coldchain(&tampered),
                "篡改 root limb {i} 必须 false"
            );
        }
        // T_max 篡改为 ≥ 2^30 的装载（位重建绑定封死）
        let mut tampered = output.clone();
        tampered.public_limbs[0] = 1 << 30;
        assert!(!verify_coldchain(&tampered), "T_max ≥ 2^30 必须 false");
    }

    #[test]
    fn prove_roundtrip_is_repeatable() {
        let first = prove_coldchain(&GOLDEN_READINGS, GOLDEN_T_MAX).unwrap();
        let second = prove_coldchain(&GOLDEN_READINGS, GOLDEN_T_MAX).unwrap();
        assert!(verify_coldchain(&first));
        assert!(verify_coldchain(&second));
        assert_eq!(first.public_limbs, second.public_limbs);
    }

    #[test]
    fn tampered_proof_bytes_fail() {
        let mut output = prove_coldchain(&GOLDEN_READINGS, GOLDEN_T_MAX).unwrap();
        if let Some(b) = output.proof.last_mut() {
            *b ^= 0xFF;
        }
        assert!(!verify_coldchain(&output));
    }

    /// 见证 publics 与 host 链根一致性（不走证明，快速回归）。
    #[test]
    fn witness_publics_match_host_root() {
        for (readings, t_max) in [
            (GOLDEN_READINGS, GOLDEN_T_MAX),
            ([0u32; NUM_READINGS], 0u32),
            ([12345, 1, 2, 3, 4, 5, 6, 7], 12345),
        ] {
            let root = coldchain_root(&readings);
            let expected: Vec<u32> = (0..8)
                .map(|i| u32::from_le_bytes(root.as_bytes()[4 * i..4 * i + 4].try_into().unwrap()))
                .collect();
            let witness = build_witness(&readings, t_max);
            assert_eq!(witness.publics[0].as_canonical_u32(), t_max);
            let got: Vec<u32> = witness.publics[1..]
                .iter()
                .map(|e| e.as_canonical_u32())
                .collect();
            assert_eq!(
                got, expected,
                "读数 {:?} 的 root limb 必须与 host 一致",
                readings
            );
        }
    }

    /// 对照组：诚实 witness 通过 debug 约束校验路径。
    #[test]
    fn honest_witness_passes_constraint_check() {
        use p3_air::check_constraints;
        let witness = build_witness(&GOLDEN_READINGS, GOLDEN_T_MAX);
        let publics: Vec<KoalaBear> = witness.publics.to_vec();
        let air = ColdchainAir::new();
        check_constraints(&air, &witness.trace, &publics);
    }

    /// 恶意 trace 回归 1：违规读数（t_2 = 2501 > T_max = 2500）强行
    /// 构造 trace（host 链按违规读数计算），喂 check_constraints 断言
    /// 被比较链终局约束拒绝。
    #[test]
    fn malicious_violating_reading_rejected() {
        use p3_air::check_constraints;
        let readings = [2350, 2400, 2501, 2415, 2390, 2365, 2420, 2375];
        // publics 取「合规口径」：T_max = 2500 + 违规读数的诚实链根
        let witness = build_witness(&readings, 2501); // 位比较按 2501 全通过
        let mut publics = witness.publics;
        publics[0] = KoalaBear::from_int(2500u32); // publics 声称 T_max = 2500
        let trace = RowMajorMatrix::new(witness.trace.values, TOTAL_COLS);
        let publics: Vec<KoalaBear> = publics.to_vec();
        let air = ColdchainAir::new();
        let result = std::panic::catch_unwind(|| {
            check_constraints(&air, &trace, &publics);
        });
        assert!(
            result.is_err(),
            "违规读数对缩小的 T_max publics 必须被位重建绑定拒绝"
        );
    }

    /// 恶意 trace 回归 2：位重建断裂（翻转一个 xb 位不更新累积器）。
    #[test]
    fn malicious_bit_reconstruction_rejected() {
        use p3_air::check_constraints;
        let witness = build_witness(&GOLDEN_READINGS, GOLDEN_T_MAX);
        let mut values = witness.trace.values.clone();
        // 块 0 位区内某行的 xb 翻转（仍布尔），该 30 位累积链断裂
        let r = 5;
        values[r * TOTAL_COLS + XB_COL] =
            KoalaBear::from_int(1u32) - values[r * TOTAL_COLS + XB_COL];
        let trace = RowMajorMatrix::new(values, TOTAL_COLS);
        let publics: Vec<KoalaBear> = witness.publics.to_vec();
        let air = ColdchainAir::new();
        let result = std::panic::catch_unwind(|| {
            check_constraints(&air, &trace, &publics);
        });
        assert!(result.is_err(), "位重建断裂的 trace 必须被拒绝");
    }

    /// 恶意 trace 回归 3：伪造 lt 标志（某读数 > T_max 却强置 lt = 1）。
    ///
    /// 构造：读数全 2^30−1 > T_max = 0，所有位 x_i = 1、b_i = 0；
    /// 从块 0 位区第 2 行起把 lt 置 1——若无约束 8 的 lt 转移钉死
    /// （前值 + win'，win 被 eqp·bb·(1−xb) 值钉死），zend 终局
    /// lt + eq = 1 将被「蒙混」通过。
    #[test]
    fn malicious_forged_lt_flag_rejected() {
        use p3_air::check_constraints;
        let readings = [MAX_VALUE - 1; NUM_READINGS];
        let witness = build_witness(&readings, 0);
        let mut values = witness.trace.values.clone();
        // 块 0 位区行 1..29 强置 lt = 1（位区外冻结值顺带携带）
        for r in 1..CHAIN_ROWS {
            values[r * TOTAL_COLS + LT_COL] = KoalaBear::from_int(1u32);
        }
        let trace = RowMajorMatrix::new(values, TOTAL_COLS);
        let publics: Vec<KoalaBear> = witness.publics.to_vec();
        let air = ColdchainAir::new();
        let result = std::panic::catch_unwind(|| {
            check_constraints(&air, &trace, &publics);
        });
        assert!(result.is_err(), "伪造 lt 标志的 trace 必须被拒绝");
    }

    /// 恶意 trace 回归 4：伪造组间 prev 传递（块 3 的 pv 换成假词但
    /// publics 不变）——链输出失配使 root 绑定暴露攻击。
    #[test]
    fn malicious_forged_prev_chaining_rejected() {
        use p3_air::check_constraints;
        let witness = build_witness(&GOLDEN_READINGS, GOLDEN_T_MAX);
        let mut values = witness.trace.values.clone();
        // 块 3 的 pv 各 limb 加 1（块内常量列整体篡改）
        for r in 3 * BLOCK_ROWS..4 * BLOCK_ROWS {
            for i in 0..RATE {
                values[r * TOTAL_COLS + PV0_COL + i] += KoalaBear::from_int(1u32);
            }
        }
        let trace = RowMajorMatrix::new(values, TOTAL_COLS);
        let publics: Vec<KoalaBear> = witness.publics.to_vec();
        let air = ColdchainAir::new();
        let result = std::panic::catch_unwind(|| {
            check_constraints(&air, &trace, &publics);
        });
        assert!(result.is_err(), "伪造组间 prev 传递的 trace 必须被拒绝");
    }
}
