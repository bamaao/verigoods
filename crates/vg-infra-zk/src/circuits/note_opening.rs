//! note_opening 电路：证明「知道 Poseidon2 Note 承诺 C 的前像」。
//!
//! ## 语义
//!
//! - **公开输入**：C 的 8 个 limb（各 canonical u32，即 host 侧
//!   [`vg_infra_crypto::poseidon::poseidon_note_commitment`] squeeze 输出
//!   的 8 × u32 小端值，[`KoalaBear::from_int`] 装载）；
//! - **私有见证**：完整前像 limb 序列（各 32B 词 × 8 limb + sentinel 1 +
//!   零补齐），由 [`prove_note_opening`] 从 parts 电路外展开：n 词展开为
//!   8n + 8 limb = n + 1 个吸收块，黄金 6 词即 56 limb = 7 块。
//!
//! 黄金锚点：黄金 Note 的 6 词前像（与 vg-domain 黄金向量一致，
//! hex 字面复刻）→ C =
//! `a161d8663eae644891afc05c9c9b4b42c7100a4d04e5882a48835b4c5e0f857d`
//! （见本文件测试 `golden_note_proves_and_verifies`）。
//!
//! ## AIR 结构（Task 12/13 扩展时以此为准）
//!
//! trace 每行承载**一次完整 Poseidon2 置换**（复用 p3-poseidon2-air 的
//! 列布局与约束语义，逐轮重算），总列宽 = 164 + 8 + 1 = 173：
//!
//! | 列区间 | 宽度 | 语义 |
//! |---|---|---|
//! | `0..164` | 164 | `Poseidon2Cols<16, 3, 0, 4, 20>`：`inputs[16]`、4 初始全轮（各 `post[16]`）、20 部分轮（各 `post_sbox`）、4 终末全轮（各 `post[16]`） |
//! | `164..172` | 8 | `block[8]`：本行置换前注入 rate 槽的吸收块（私有见证） |
//! | `172` | 1 | `t`：sponge 链布尔标志（0 = 填充行，1 = 真实行；单调 0→1） |
//!
//! 行数：真实行数 = 1（label 域分隔初始化置换）+ n + 1（吸收块置换），
//! 前端补**填充行**至 2 的幂（且至少 1 行，保证 start 行由唯一的
//! t 0→1 转移标记；填充行同样满足全部约束：链式吸收零块）。黄金
//! 6 词 → 8 真实行 + 8 填充行 = 16 行。
//!
//! ## 约束要点（max degree = 3，来自 S-box x³）
//!
//! 1. **置换约束**（所有行）：镜像 p3-poseidon2-air 的 eval——外部线性层
//!    起始，4 初始全轮（+rc → x³ → 外部线性层 → assert post）、20 部分轮
//!    （state[0] +rc → x³ → assert post_sbox → 内部线性层）、4 终末全轮；
//!    `ending_full_rounds[3].post` 即该行置换输出；
//! 2. **t 布尔**（所有行）：`t * (t - 1) = 0`；**首行 `t = 0`**（关键
//!    soundness 约束：若允许 t 从首行即 1，则 g = t_next - t_local 恒
//!    为 0，start 行的 label 锚定守卫全部失效，攻击者可从自由首状态
//!    伪造 publics==C 的证明）、末行 `t = 1`；
//! 3. **单调**（转移）：`t_local - t_local * t_next = 0`，故
//!    `g = t_next - t_local` 是唯一的 0→1 指示子（start 行进入标志）；
//! 4. **链式吸收**（转移，g = 0 时）：rate 槽
//!    `inputs_next[i] = post_local[i] + block_next[i]`（i < 8）、
//!    capacity 槽 `inputs_next[i] = post_local[i]`（i ≥ 8）；
//! 5. **start 行**（转移，g = 1 时）：`inputs_next[0..8] = L`（域分隔
//!    label limb，常量）、`inputs_next[8..16] = 0`；
//! 6. **公开绑定**（末行）：`post[0..8] = publics[0..8]`。
//!
//! 可靠性论证：首行 t = 0 与末行 t = 1 加上 t 单调布尔，迫使存在唯一
//! 的 0→1 转移（start 行）；末行输出沿链式约束回溯到该 start 行
//! （label 初始化），因此证明通过 ⟺ prover 知道一条从 label 起、以
//! rate = C 结尾的吸收块序列（即 C 的填充前像；6 词 note 结构由
//! host 侧见证构造保证，电路层面块内容为自由见证——如需电路内强制
//! sentinel 结构可在 Task 12 扩展 block 列约束）。回归测试
//! `malicious_t_equivalent_one_trace_rejected` 锁定该攻击面已封。
//!
//! ## STARK 配置（非零知识，见 crate 根文档诚实边界）
//!
//! 组装模板取自 p3-uni-stark 0.7.0-rc.1 `tests/fib_air.rs` 的 two-adic
//! 配置，Val/Challenge/哈希全部换成 KoalaBear 系：
//! - PCS：`TwoAdicFriPcs`（`Radix2DitParallel` DFT + `MerkleTreeMmcs`
//!   承诺 + degree-4 二项扩域 challenge）；
//! - 哈希/压缩/挑战者：`default_koalabear_poseidon2_16` 派生的
//!   `PaddingFreeSponge` / `TruncatedPermutation` / `DuplexChallenger`
//!   （与 host 侧承诺复用同一置换实例，勿复制常量）；
//! - FRI：log_blowup 3、num_queries 40、query PoW 12 bit
//!   （conjectured soundness ≈ 3×40 + 12 = 132 bit；上生产前复核）。
//!
//! ## ProofOutput
//!
//! `proof` 为 postcard 序列化的 `p3_uni_stark::Proof<NoteConfig>` 字节，
//! `public_limbs` 为公开输入的 8 个 canonical u32 limb（小端拼接即 32B
//! 承诺 C）。Task 13 将其转换为 domain 的 `ProofBundle`。

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
use vg_infra_crypto::keccak256;
use vg_infra_crypto::poseidon::to_field_le;

use crate::ZkError;

/// 电路标识（Task 13 PlonkyProver 的 circuit@version 口径）。
pub const NOTE_OPENING_CIRCUIT_ID: &str = "note_opening";
/// 电路版本（约束/配置变更时递增，proof 不跨版本兼容）。
pub const NOTE_OPENING_CIRCUIT_VERSION: u64 = 1;

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
/// trace 最大高度（KoalaBear 2-adicity = 24，留余量防御超长 parts）。
const MAX_LOG_HEIGHT: usize = 20;
/// 公开输入个数（C 的 8 limb）。
const NUM_PUBLICS: usize = 8;

/// 置换列区宽度（p3-poseidon2-air 同款列布局的 `num_cols`）。
const PERM_COLS: usize =
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
/// 本电路总列宽：置换列 + block[8] + t[1]。
const TOTAL_COLS: usize = PERM_COLS + RATE + 1;
/// t 标志列下标。
const T_COL: usize = PERM_COLS + RATE;

// ---- StarkConfig 组装 ----

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
/// 本电路的 STARK 配置类型（`ProofOutput::proof` 即其 `Proof` 序列化字节）。
type NoteConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// 组装 STARK 配置（确定性：哈希置换全部来自 KoalaBear 预置常量）。
fn note_config() -> NoteConfig {
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
    NoteConfig::new(pcs, challenger)
}

/// 域分隔 label 的 8 个 limb（与 host 侧 sponge 第 1 步一致）。
fn label_limbs() -> [KoalaBear; RATE] {
    let digest = keccak256(DOMAIN_LABEL);
    let limbs = to_field_le(&digest);
    let mut out = [KoalaBear::from_int(0u32); RATE];
    out.copy_from_slice(&limbs);
    out
}

/// AIR：note_opening sponge 链（结构见模块文档）。
#[derive(Debug, Clone)]
pub struct NoteOpeningAir {
    /// 置换轮常数（与 `default_koalabear_poseidon2_16` 同源，非复制）。
    constants: RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    /// 域分隔 label limb（start 行约束用）。
    label: [KoalaBear; RATE],
}

impl NoteOpeningAir {
    /// 构造 AIR（轮常数取自 p3-koala-bear 预置常量，与 host 置换同源）。
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

impl Default for NoteOpeningAir {
    fn default() -> Self {
        Self::new()
    }
}

impl BaseAir<KoalaBear> for NoteOpeningAir {
    fn width(&self) -> usize {
        TOTAL_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLICS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // S-box x³ 为最高次（3），链式/标志约束均为 degree ≤ 2。
        Some(3)
    }
}

// 仅对 F = KoalaBear 的 builder 实现（uni-stark 的 prove/verify 与 debug
// 约束检查均以 Val<SC> = KoalaBear 实例化）。
impl<AB> Air<AB> for NoteOpeningAir
where
    AB: AirBuilder<F = KoalaBear>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();

        // 1. 置换约束（所有行，仅引用 local）
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

        // 2. t 布尔（所有行，仅 local）
        let t_local: AB::Expr = local[T_COL].into();
        builder.assert_zero(t_local.clone() * (t_local.clone() - KoalaBear::from_int(1u32)));
        // 首行 t = 0（关键：封死「t≡1 使 g 全为 0、label 锚定失效」的
        // 伪造链攻击——没有此约束，攻击者可令全部转移的 start 守卫
        // 失效，从自由首状态逐行反解出 publics==C 的伪证）
        builder.when_first_row().assert_zero(local[T_COL]);

        // 6. 公开绑定 + 末行 t = 1（先拷贝 publics 以结束不可变借用）
        let publics: [AB::PublicVar; RATE] = builder.public_values()[..RATE]
            .try_into()
            .expect("num_public_values = 8 保证切片长度");
        let mut when_last = builder.when_last_row();
        when_last.assert_eq(local[T_COL], KoalaBear::from_int(1u32));
        for i in 0..RATE {
            when_last.assert_eq(out_local[i], publics[i]);
        }
        drop(when_last);

        // 3/4/5. 转移约束
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
        // 单调：t_local - t_local * t_next = 0 ⟹ g = t_next - t_local ∈ {0,1}
        let g = t_next.clone() - t_local;
        let one: AB::Expr = KoalaBear::from_int(1u32).into();
        let one_minus_g = one.clone() - g.clone();

        let mut when_transition = builder.when_transition();
        // 单调：t_local * (1 - t_next) = 0（t 一旦为 1 不再回 0）
        when_transition.assert_zero(local[T_COL] * (one.clone() - next[T_COL]));

        // 链式吸收（g = 0 时生效）
        for i in 0..RATE {
            let chain = inputs_next[i] - out_local[i] - next[PERM_COLS + i];
            when_transition.assert_zero(one_minus_g.clone() * chain);
        }
        for i in RATE..WIDTH {
            when_transition.assert_zero(one_minus_g.clone() * (inputs_next[i] - out_local[i]));
        }
        // start 行（g = 1）：inputs = label || 零
        for (input_next, label_i) in inputs_next.iter().zip(self.label) {
            when_transition.assert_zero(g.clone() * (*input_next - label_i));
        }
        for input_next in inputs_next.iter().take(WIDTH).skip(RATE) {
            when_transition.assert_zero(g.clone() * *input_next);
        }
    }
}

/// 按行重算一次完整 Poseidon2 置换（镜像 p3-poseidon2-air 的 eval 语义）。
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

/// 展开前像 limb（电路外）：各词 8 limb + sentinel 1 + 零补齐至 RATE 倍数。
fn expand_limbs(parts: &[[u8; 32]]) -> Vec<KoalaBear> {
    let mut limbs = Vec::with_capacity(parts.len() * RATE + RATE);
    for word in parts {
        limbs.extend(to_field_le(word));
    }
    limbs.push(KoalaBear::from_int(1u32));
    while !limbs.len().is_multiple_of(RATE) {
        limbs.push(KoalaBear::from_int(0u32));
    }
    limbs
}

/// 见证与公开输入（prove/verify 内部使用）。
struct Witness {
    trace: RowMajorMatrix<KoalaBear>,
    publics: [KoalaBear; NUM_PUBLICS],
}

/// 构造 trace 与公开输入（结构见模块文档「AIR 结构」小节）。
fn build_witness(parts: &[[u8; 32]]) -> Result<Witness, ZkError> {
    if parts.is_empty() {
        return Err(ZkError::InvalidWitness("parts 为空".into()));
    }

    let blocks: Vec<[KoalaBear; RATE]> = expand_limbs(parts)
        .chunks_exact(RATE)
        .map(|c| c.try_into().expect("chunks_exact 保证 8 limb"))
        .collect();
    let real_rows = blocks.len() + 1;

    // 至少 1 行填充（保证 start 行由 0→1 转移标记），再取 2 的幂。
    let height = (real_rows + 1).next_power_of_two();
    if height > (1usize << MAX_LOG_HEIGHT) {
        return Err(ZkError::InvalidWitness(format!(
            "parts 过长：trace 高度 2^{} 超上限 2^{MAX_LOG_HEIGHT}",
            height.trailing_zeros()
        )));
    }
    let pad = height - real_rows;

    // 逐置换输入序列：填充行（dummy 链，block 全零）+ label 初始化 + 吸收块。
    let perm_host = default_koalabear_poseidon2_16();
    let label = label_limbs();

    let mut inputs: Vec<[KoalaBear; WIDTH]> = Vec::with_capacity(height);
    let mut dummy = [KoalaBear::from_int(0u32); WIDTH];
    for _ in 0..pad {
        inputs.push(dummy);
        perm_host.permute_mut(&mut dummy);
    }
    // start 行：state = 0，rate += label，即置换输入 = label || 零。
    let mut state = [KoalaBear::from_int(0u32); WIDTH];
    state[..RATE].copy_from_slice(&label);
    inputs.push(state);
    perm_host.permute_mut(&mut state);
    // 吸收块行：rate += block → 置换。
    for block in &blocks {
        for i in 0..RATE {
            state[i] += block[i];
        }
        inputs.push(state);
        perm_host.permute_mut(&mut state);
    }
    debug_assert_eq!(inputs.len(), height);

    // 公开输入：最终状态 rate 槽（= C 的 8 limb）。
    let mut publics = [KoalaBear::from_int(0u32); NUM_PUBLICS];
    publics.copy_from_slice(&state[..RATE]);

    // 用 p3-poseidon2-air 的生成器填充置换列，再拼装 block / t 列。
    let air = NoteOpeningAir::new();
    let perm_matrix = generate_trace_rows::<
        KoalaBear,
        GenericPoseidon2LinearLayersKoalaBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, &air.constants, 0);

    let mut values = vec![KoalaBear::from_int(0u32); height * TOTAL_COLS];
    for r in 0..height {
        let src = &perm_matrix.values[r * PERM_COLS..(r + 1) * PERM_COLS];
        values[r * TOTAL_COLS..r * TOTAL_COLS + PERM_COLS].copy_from_slice(src);
        // block 列：填充行全零；start 行 = label（不参与约束，见证自洽）；
        // 其余 = 对应吸收块。
        if r == pad {
            values[r * TOTAL_COLS + PERM_COLS..r * TOTAL_COLS + PERM_COLS + RATE]
                .copy_from_slice(&label);
        } else if r > pad {
            let block = &blocks[r - pad - 1];
            values[r * TOTAL_COLS + PERM_COLS..r * TOTAL_COLS + PERM_COLS + RATE]
                .copy_from_slice(block);
        }
        // t 列：真实行 = 1。
        values[r * TOTAL_COLS + T_COL] = KoalaBear::from_int(u32::from(r >= pad));
    }

    Ok(Witness {
        trace: RowMajorMatrix::new(values, TOTAL_COLS),
        publics,
    })
}

/// note_opening 证明输出。
///
/// - `proof`：postcard 序列化的 `p3_uni_stark::Proof<NoteConfig>` 字节
///   （配置随 [`NOTE_OPENING_CIRCUIT_VERSION`] 锁定，不跨版本兼容）；
/// - `public_limbs`：公开输入 C 的 8 个 canonical u32 limb（小端拼接
///   即 32B 承诺，与 host 侧 `poseidon_note_commitment` 输出一致）。
///
/// Task 13 将此结构转换为 domain 的 `ProofBundle`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofOutput {
    /// 证明字节（postcard）。
    pub proof: Vec<u8>,
    /// 公开输入（C 的 8 limb，canonical u32）。
    pub public_limbs: [u32; NUM_PUBLICS],
}

/// 为 parts 计算 note_opening 证明。
///
/// 内部展开前像 limb 与填充（黄金 6 词 → 56 limb = 7 块；一般 n 词 →
/// n + 1 块），构造 trace 后经 p3-uni-stark prove。空 parts 返回
/// [`ZkError::InvalidWitness`]（不 panic）。随机性仅来自证明系统内部
/// 挑战采样，无显式 nonce。
pub fn prove_note_opening(parts: &[[u8; 32]]) -> Result<ProofOutput, ZkError> {
    let witness = build_witness(parts)?;
    let config = note_config();
    let air = NoteOpeningAir::new();
    let publics: Vec<KoalaBear> = witness.publics.to_vec();
    let proof = prove(&config, &air, witness.trace, &publics);
    let bytes = postcard::to_allocvec(&proof).map_err(|e| ZkError::Serialization(e.to_string()))?;
    let mut public_limbs = [0u32; NUM_PUBLICS];
    for (i, v) in witness.publics.iter().enumerate() {
        public_limbs[i] = v.as_canonical_u32();
    }
    Ok(ProofOutput {
        proof: bytes,
        public_limbs,
    })
}

/// 验证 note_opening 证明（publics 取 `output.public_limbs`）。
///
/// 任何篡改（证明字节或公开 limb）返回 false，不 panic。
pub fn verify_note_opening(output: &ProofOutput) -> bool {
    let Ok(proof) = postcard::from_bytes(&output.proof) else {
        return false;
    };
    let publics: Vec<KoalaBear> = output
        .public_limbs
        .iter()
        .map(|l| KoalaBear::from_int(*l))
        .collect();
    let config = note_config();
    let air = NoteOpeningAir::new();
    verify(&config, &air, &proof, &publics).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use vg_infra_crypto::poseidon::poseidon_note_commitment;

    /// 黄金 Note 的 6 词前像（与 vg-domain 黄金向量一致，hex 字面复刻；
/// 与 vg-infra-crypto fixture 逐字一致）。
    fn golden_parts() -> Vec<[u8; 32]> {
        let word = |hex: &str| -> [u8; 32] { hex::decode(hex).unwrap().try_into().unwrap() };
        vec![
            word("a4c41c2383a5fd0b250bce28a902ebfb3480349f8714a9232a3dd279831f061d"),
            word("0ac2d6796d51fb5318755791b4b3e1e9180d58e74167ea2a71c81b4cbe41be52"),
            word("1111111111111111111111111111111111111111111111111111111111111111"),
            word("0700000000000000000000000000000000000000000000000000000000000000"),
            word("2200000000000000000000000000000000000000000000000000000000000000"),
            word("0000000000000000000000000000000033445566000000000000000000000000"),
        ]
    }

    /// 黄金承诺 hex（vg-infra-crypto golden fixture 锁定值）。
    const GOLDEN_C_HEX: &str = "a161d8663eae644891afc05c9c9b4b42c7100a4d04e5882a48835b4c5e0f857d";

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
    fn golden_note_proves_and_verifies() {
        let parts = golden_parts();
        // 前置对齐：host 侧承诺 == 黄金 C
        assert_eq!(
            poseidon_note_commitment(&parts).as_hex(),
            GOLDEN_C_HEX,
            "host 侧承诺必须先与 golden fixture 对齐"
        );

        let start = Instant::now();
        let output = prove_note_opening(&parts).expect("黄金见证 prove 应成功");
        let prove_secs = start.elapsed().as_secs_f64();

        let start = Instant::now();
        assert!(verify_note_opening(&output), "黄金证明 verify 必须 true");
        let verify_secs = start.elapsed().as_secs_f64();

        // 公开输入 == C 的 8 limb（逐 limb + hex 全量双口径断言）
        assert_eq!(output.public_limbs, golden_c_limbs());
        assert_eq!(
            hex::encode(
                output
                    .public_limbs
                    .iter()
                    .flat_map(|l| l.to_le_bytes())
                    .collect::<Vec<u8>>()
            ),
            GOLDEN_C_HEX
        );
        println!("golden prove: {prove_secs:.2}s, verify: {verify_secs:.2}s");
    }

    #[test]
    fn wrong_public_input_fails() {
        let parts = golden_parts();
        let output = prove_note_opening(&parts).expect("prove 应成功");
        for i in 0..8 {
            let mut tampered = output.clone();
            tampered.public_limbs[i] ^= 1;
            assert!(
                !verify_note_opening(&tampered),
                "篡改公开 limb {i} 后 verify 必须 false"
            );
        }
    }

    #[test]
    fn tampered_witness_fails() {
        let parts = golden_parts();
        let output = prove_note_opening(&parts).expect("prove 应成功");
        assert!(verify_note_opening(&output));

        // 前像任一词改动 → host 侧重算承诺 ≠ C
        for w in 0..6 {
            let mut tampered_parts = parts.clone();
            tampered_parts[w][0] ^= 0x01;
            assert_ne!(
                poseidon_note_commitment(&tampered_parts).as_hex(),
                GOLDEN_C_HEX
            );
        }

        // 篡改见证（词 0 首字节翻转）prove 后，对原 C 的公开输入 verify false
        let mut tampered_parts = parts.clone();
        tampered_parts[0][0] ^= 0x01;
        let tampered_output = prove_note_opening(&tampered_parts).expect("篡改见证 prove 应成功");
        let mut against_original = tampered_output;
        against_original.public_limbs = golden_c_limbs();
        assert!(
            !verify_note_opening(&against_original),
            "篡改见证的证明对原 C 必须 verify false"
        );
    }

    #[test]
    fn empty_parts_rejected() {
        // 空 parts：返回 ZkError，不 panic
        let err = prove_note_opening(&[]).expect_err("空 parts 必须被拒绝");
        assert!(matches!(err, ZkError::InvalidWitness(_)));
    }

    #[test]
    fn prove_roundtrip_is_repeatable() {
        // 同 witness 两次 prove 均可 verify（proof 字节可不同：挑战随机）
        let parts = golden_parts();
        let first = prove_note_opening(&parts).expect("第一次 prove 应成功");
        let second = prove_note_opening(&parts).expect("第二次 prove 应成功");
        assert!(verify_note_opening(&first));
        assert!(verify_note_opening(&second));
        assert_eq!(first.public_limbs, second.public_limbs);
    }

    #[test]
    fn tampered_proof_bytes_fail() {
        // 序列化字节篡改 → false（防御性补充用例）
        let parts = golden_parts();
        let mut output = prove_note_opening(&parts).expect("prove 应成功");
        if let Some(b) = output.proof.last_mut() {
            *b ^= 0xFF;
        }
        assert!(!verify_note_opening(&output));
    }

    /// 恶意 trace 回归：封堵「t≡1 伪造链」攻击（首行 t=0 约束）。
    ///
    /// 攻击面：修复前若 t 允许从首行即 1，则 g = t_next - t_local 恒为 0，
    /// 所有 start 行 label 锚定守卫（g*(...)）失效，首行 inputs 完全自由
    /// ——由置换可逆性可逐行反解并以自由 block 吸收差值，在不知前像的
    /// 情况下伪造 publics==C 的证明（height=1 时平凡成立）。
    ///
    /// 构造：height=1 的「完美」恶意 trace——置换列全真（generate_trace_rows
    /// 从任意输入生成）、block 全零、t=1、publics 取该行真实输出（即一个
    /// 修复前可通过全部约束的伪证），喂给 p3_air::check_constraints（与
    /// prove 内 DebugConstraintBuilder 同一条逐行约束校验路径），断言被拒。
    #[test]
    fn malicious_t_equivalent_one_trace_rejected() {
        use p3_air::check_constraints;

        // 单行 trace：置换输入任意（攻击者自选），其余列按攻击者最优填法。
        let attacker_input = [KoalaBear::from_int(0x12345678u32); WIDTH];
        let air = NoteOpeningAir::new();
        let perm_matrix = generate_trace_rows::<
            KoalaBear,
            GenericPoseidon2LinearLayersKoalaBear,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(vec![attacker_input], &air.constants, 0);

        let mut values = perm_matrix.values.clone();
        values.extend_from_slice(&[KoalaBear::from_int(0u32); RATE]); // block 全零
        values.push(KoalaBear::from_int(1u32)); // t = 1（恶意：首行即 1）
        let trace = RowMajorMatrix::new(values, TOTAL_COLS);

        // publics 取该行真实输出 rate 槽（末行公开绑定因此满足）。
        let perm_cols: &Poseidon2Cols<
            KoalaBear,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = trace.values[..PERM_COLS].borrow();
        let publics: Vec<KoalaBear> =
            perm_cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[..RATE].to_vec();

        // 约束校验必须失败（首行 t=0 违规；修复前此 trace 通过全部约束）
        let result = std::panic::catch_unwind(|| {
            check_constraints(&air, &trace, &publics);
        });
        assert!(
            result.is_err(),
            "t≡1 单行伪证必须被首行 t=0 约束拒绝"
        );
    }

    /// 对照组：诚实 witness 必须通过同一条 debug 约束校验路径。
    #[test]
    fn honest_witness_passes_constraint_check() {
        use p3_air::check_constraints;
        let witness = build_witness(&golden_parts()).expect("见证构造应成功");
        let publics: Vec<KoalaBear> = witness.publics.to_vec();
        let air = NoteOpeningAir::new();
        check_constraints(&air, &witness.trace, &publics);
    }

    /// AIR 见证与 host 置换的一致性（不走证明，快速回归）：
    /// build_witness 的 publics == host 承诺 limb。
    #[test]
    fn witness_publics_match_host_commitment() {
        for parts in [
            golden_parts(),
            vec![[7u8; 32]; 1],
            vec![[9u8; 32]; 5],
            vec![[3u8; 32]; 31],
        ] {
            let c = poseidon_note_commitment(&parts);
            let expected: Vec<u32> = (0..8)
                .map(|i| u32::from_le_bytes(c.as_bytes()[4 * i..4 * i + 4].try_into().unwrap()))
                .collect();
            let witness = build_witness(&parts).expect("见证构造应成功");
            let got: Vec<u32> = witness
                .publics
                .iter()
                .map(|e| e.as_canonical_u32())
                .collect();
            assert_eq!(got, expected);
        }
    }
}
