//! # Prover 分发层：[`ProofProver`] 端口的 vg-infra-zk 实现。
//!
//! 两个实现：
//! - [`ProverDispatcher`]：按 `CircuitSpec.id + version` 分发到本 crate
//!   三个真实 Plonky3 电路（note_opening / range_check / coldchain_max）；
//! - [`TransparentProver`]：keccak 签名式回执（**仅测试用**，见其文档）。
//!
//! ## witness / publics 映射规范（写死，供 Task 19 应用层使用）
//!
//! `FieldElement` 为 32 字节小端载体。各电路的 `Witness.secrets` 与
//! `CircuitSpec.public_inputs` / `ProofBundle.publics` 编码：
//!
//! | 电路 | secrets | public_inputs / publics |
//! |---|---|---|
//! | `note_opening@1` | 6 个前像词（各=一个 32B 词原样） | C 的 8 limb（各=低 4 字节 LE u32、余 28 字节零） |
//! | `range_check@2` | [词(x), 词(salt)]：词(x) = bytes 0..12 为 3 个 30-bit chunk LE、余零；词(salt) = bytes 0..16 零、bytes 16..32 = salt | [B_c0, B_c1, B_c2, C×8] 11 个（B chunk 与 C limb 均低 4 字节 LE u32） |
//! | `coldchain_max@1` | 8 个 t_i 词（各=低 4 字节 LE u32、余 28 字节零，值 < 2^30） | [T_max, root×8] 9 个（低 4 字节 LE u32） |
//!
//! `ProofBundle.proof` 字节 = postcard 序列化的各电路 `ProofOutput.proof`
//! （格式仅本仓内部口径，不跨版本兼容；电路版本变更时 proof 即失效）。
//!
//! ## 错误映射
//!
//! - 未注册的电路 ID 或版本不符 → `DomainError::InvalidInput`
//!   （"未知电路 …"）；
//! - witness 数量/编码不合法、公开输入与计算结果不一致 →
//!   `DomainError::InvalidInput`；
//! - [`ZkError`] 统一映射 `InvalidInput`（InvalidWitness /
//!   Serialization 均为调用侧输入问题，infra 层不越权映射其它错误）；
//! - verify 侧对合法路由的电路永不 Err（解码失败等返回 `Ok(false)`）。

use async_trait::async_trait;
use vg_domain::ports::{
    CircuitSpec, FieldElement, ProofBundle, ProofProver, Witness,
};
use vg_domain::shared::DomainError;
#[cfg(any(test, feature = "test-util"))]
use vg_infra_crypto::keccak256;

use crate::circuits::coldchain::{
    prove_coldchain, verify_coldchain, ColdchainProofOutput, COLDCHAIN_MAX_CIRCUIT_ID,
    COLDCHAIN_MAX_CIRCUIT_VERSION,
};
use crate::circuits::note_opening::{
    prove_note_opening, verify_note_opening, ProofOutput, NOTE_OPENING_CIRCUIT_ID,
    NOTE_OPENING_CIRCUIT_VERSION,
};
use crate::circuits::range_check::{
    prove_range_check, verify_range_check, RangeProofOutput, RANGE_CHECK_CIRCUIT_ID,
    RANGE_CHECK_CIRCUIT_VERSION,
};
use crate::ZkError;

/// coldchain / range 的共同编码边界（2^30 < p，canonical 单 limb）。
const MAX_VALUE: u32 = 1 << 30;
/// range_check 词(x) 的 chunk 装载字节数（3 chunk × 4 字节）。
const RANGE_CHUNK_BYTES: usize = 12;

/// FieldElement → u32（低 4 字节 LE；余 28 字节必须为零，
/// 否则违反映射规范，返回 InvalidInput）。
fn fe_to_u32(fe: &FieldElement) -> Result<u32, DomainError> {
    let b = fe.as_bytes();
    if b[4..].iter().any(|&x| x != 0) {
        return Err(DomainError::InvalidInput(
            "FieldElement 高 28 字节必须为零（u32 limb 装载规范）".into(),
        ));
    }
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// u32 → FieldElement（低 4 字节 LE、余零）。
fn u32_to_fe(v: u32) -> FieldElement {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&v.to_le_bytes());
    FieldElement::from_bytes(b)
}

/// u32 limb 列 → FieldElement 列。
fn limbs_to_fes(limbs: &[u32]) -> Vec<FieldElement> {
    limbs.iter().map(|l| u32_to_fe(*l)).collect()
}

/// ZkError → DomainError（统一 InvalidInput，见模块文档）。
fn map_zk_error(e: ZkError) -> DomainError {
    DomainError::InvalidInput(format!("ZK 证明失败：{e}"))
}

/// 断言两组公开输入逐元素相等（不一致 → InvalidInput，错误信息携带
/// 电路 id@version 与首个失配位置）。
fn check_publics(
    circuit: &CircuitSpec,
    expected: &[u32],
    given: &[FieldElement],
) -> Result<(), DomainError> {
    let given_limbs: Vec<u32> = given.iter().map(fe_to_u32).collect::<Result<_, _>>()?;
    if expected != given_limbs {
        let pos = expected
            .iter()
            .zip(given_limbs.iter())
            .position(|(a, b)| a != b);
        let detail = match pos {
            Some(i) => format!(
                "publics[{i}] 不一致：期望 {:#x} 实得 {:#x}",
                expected[i], given_limbs[i]
            ),
            None => format!(
                "长度不一致：期望 {} 实得 {}",
                expected.len(),
                given_limbs.len()
            ),
        };
        return Err(DomainError::InvalidInput(format!(
            "电路 {}@{} {}",
            circuit.id, circuit.version, detail
        )));
    }
    Ok(())
}

/// 真实电路分发器：按 `circuit.id + version` 路由到对应 Plonky3 电路。
///
/// prove 侧各电路内部校验 witness 数量/编码；verify 侧**显式路由**：
/// note_opening 走无预处理列的 `verify`，range_check / coldchain_max
/// 走 `verify_with_preprocessed`（同型 config 互解不报错，若不显式
/// 路由会以错误的 AIR 校验导致不可预期的假阳性/假阴性）。
#[derive(Debug, Clone, Copy, Default)]
pub struct ProverDispatcher;

#[async_trait]
impl ProofProver for ProverDispatcher {
    async fn prove(
        &self,
        circuit: &CircuitSpec,
        witness: &Witness,
    ) -> Result<ProofBundle, DomainError> {
        match (circuit.id.as_str(), circuit.version) {
            (NOTE_OPENING_CIRCUIT_ID, NOTE_OPENING_CIRCUIT_VERSION) => {
                if witness.secrets.len() != 6 {
                    return Err(DomainError::InvalidInput(
                        "note_opening 见证必须为 6 个前像词".into(),
                    ));
                }
                if circuit.public_inputs.len() != 8 {
                    return Err(DomainError::InvalidInput(
                        "note_opening 公开输入必须为 C 的 8 个 limb".into(),
                    ));
                }
                let parts: Vec<[u8; 32]> = witness
                    .secrets
                    .iter()
                    .map(|w| *w.as_bytes())
                    .collect();
                let output = prove_note_opening(&parts).map_err(map_zk_error)?;
                let publics = limbs_to_fes(&output.public_limbs);
                check_publics(circuit, &output.public_limbs, &circuit.public_inputs)?;
                Ok(ProofBundle {
                    circuit_id: circuit.id.clone(),
                    version: circuit.version,
                    proof: output.proof,
                    publics,
                })
            }
            (RANGE_CHECK_CIRCUIT_ID, RANGE_CHECK_CIRCUIT_VERSION) => {
                if witness.secrets.len() != 2 {
                    return Err(DomainError::InvalidInput(
                        "range_check 见证必须为 [词(x), 词(salt)]".into(),
                    ));
                }
                if circuit.public_inputs.len() != 11 {
                    return Err(DomainError::InvalidInput(
                        "range_check 公开输入必须为 [B_c0, B_c1, B_c2, C×8] 11 个".into(),
                    ));
                }
                // 词(x)：bytes 0..12 = 3 个 30-bit chunk LE、余零
                let xw = witness.secrets[0].as_bytes();
                if xw[RANGE_CHUNK_BYTES..].iter().any(|&b| b != 0) {
                    return Err(DomainError::InvalidInput(
                        "range_check 词(x) 的 bytes 12..32 必须为零".into(),
                    ));
                }
                let mut x: u64 = 0;
                for j in 0..3 {
                    let chunk =
                        u32::from_le_bytes(xw[4 * j..4 * j + 4].try_into().expect("4 字节切片"));
                    if chunk >= MAX_VALUE {
                        return Err(DomainError::InvalidInput(
                            "range_check 词(x) 的 chunk 必须 < 2^30".into(),
                        ));
                    }
                    x |= (chunk as u64) << (30 * j as u32);
                }
                // 词(salt)：bytes 0..16 零、bytes 16..32 = salt
                let sw = witness.secrets[1].as_bytes();
                if sw[..16].iter().any(|&b| b != 0) {
                    return Err(DomainError::InvalidInput(
                        "range_check 词(salt) 的 bytes 0..16 必须为零".into(),
                    ));
                }
                let salt: [u8; 16] = sw[16..].try_into().expect("16 字节切片");
                // publics 前 3 个 = B chunk（整数重建 bound）
                let mut bound: u64 = 0;
                for j in 0..3 {
                    let chunk = fe_to_u32(&circuit.public_inputs[j])?;
                    if chunk >= MAX_VALUE {
                        return Err(DomainError::InvalidInput(
                            "range_check 公开 B chunk 必须 < 2^30".into(),
                        ));
                    }
                    bound |= (chunk as u64) << (30 * j as u32);
                }
                for fe in &circuit.public_inputs[3..] {
                    fe_to_u32(fe)?;
                }
                let output = prove_range_check(x, &salt, bound).map_err(map_zk_error)?;
                check_publics(circuit, &output.public_limbs, &circuit.public_inputs)?;
                Ok(ProofBundle {
                    circuit_id: circuit.id.clone(),
                    version: circuit.version,
                    proof: output.proof,
                    publics: limbs_to_fes(&output.public_limbs),
                })
            }
            (COLDCHAIN_MAX_CIRCUIT_ID, COLDCHAIN_MAX_CIRCUIT_VERSION) => {
                if witness.secrets.len() != 8 {
                    return Err(DomainError::InvalidInput(
                        "coldchain_max 见证必须为 8 个读数词".into(),
                    ));
                }
                if circuit.public_inputs.len() != 9 {
                    return Err(DomainError::InvalidInput(
                        "coldchain_max 公开输入必须为 [T_max, root×8] 9 个".into(),
                    ));
                }
                let mut readings = [0u32; 8];
                for (i, w) in witness.secrets.iter().enumerate() {
                    readings[i] = fe_to_u32(w)?;
                }
                let t_max = fe_to_u32(&circuit.public_inputs[0])?;
                let output = prove_coldchain(&readings, t_max).map_err(map_zk_error)?;
                check_publics(circuit, &output.public_limbs, &circuit.public_inputs)?;
                Ok(ProofBundle {
                    circuit_id: circuit.id.clone(),
                    version: circuit.version,
                    proof: output.proof,
                    publics: limbs_to_fes(&output.public_limbs),
                })
            }
            _ => Err(DomainError::InvalidInput(format!(
                "未知电路 {}@{}（id 或版本未注册）",
                circuit.id, circuit.version
            ))),
        }
    }

    fn verify(&self, bundle: &ProofBundle) -> Result<bool, DomainError> {
        match (bundle.circuit_id.as_str(), bundle.version) {
            (NOTE_OPENING_CIRCUIT_ID, NOTE_OPENING_CIRCUIT_VERSION) => {
                if bundle.publics.len() != 8 {
                    return Err(DomainError::InvalidInput(
                        "note_opening 公开输入必须为 8 个 limb".into(),
                    ));
                }
                let mut limbs = [0u32; 8];
                for (i, fe) in bundle.publics.iter().enumerate() {
                    limbs[i] = fe_to_u32(fe)?;
                }
                Ok(verify_note_opening(&ProofOutput {
                    proof: bundle.proof.clone(),
                    public_limbs: limbs,
                }))
            }
            (RANGE_CHECK_CIRCUIT_ID, RANGE_CHECK_CIRCUIT_VERSION) => {
                if bundle.publics.len() != 11 {
                    return Err(DomainError::InvalidInput(
                        "range_check 公开输入必须为 11 个".into(),
                    ));
                }
                let mut limbs = [0u32; 11];
                for (i, fe) in bundle.publics.iter().enumerate() {
                    limbs[i] = fe_to_u32(fe)?;
                }
                Ok(verify_range_check(&RangeProofOutput {
                    proof: bundle.proof.clone(),
                    public_limbs: limbs,
                }))
            }
            (COLDCHAIN_MAX_CIRCUIT_ID, COLDCHAIN_MAX_CIRCUIT_VERSION) => {
                if bundle.publics.len() != 9 {
                    return Err(DomainError::InvalidInput(
                        "coldchain_max 公开输入必须为 9 个".into(),
                    ));
                }
                let mut limbs = [0u32; 9];
                for (i, fe) in bundle.publics.iter().enumerate() {
                    limbs[i] = fe_to_u32(fe)?;
                }
                Ok(verify_coldchain(&ColdchainProofOutput {
                    proof: bundle.proof.clone(),
                    public_limbs: limbs,
                }))
            }
            _ => Err(DomainError::InvalidInput(format!(
                "未知电路 {}@{}（id 或版本未注册）",
                bundle.circuit_id, bundle.version
            ))),
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
/// 透明回执 Prover（**仅测试用**）。
///
/// ## ⚠ 不具零知识性与可靠性
///
/// 本实现**不是证明系统**：proof 只是
/// `keccak256(规范化串(id‖version‖publics‖secrets))` 的签名式回执，
/// 任何持有 witness 的方都能生成，不提供任何 soundness 保障；
/// 且 proof 内嵌 secrets 明文，零知识性为零。仅用于测试与本地联调
/// （Task 19 等在无 Plonky3 开销下走通端口编排）。
///
/// proof 字节布局：`[32B digest][secrets 各 32B 顺序拼接]`（digest
/// 部分 + secrets 尾巴，verify 侧据 bundle 字段 + 尾巴重算比对）。
#[derive(Debug, Clone, Copy, Default)]
pub struct TransparentProver;

#[cfg(any(test, feature = "test-util"))]
impl TransparentProver {
    /// 规范化串：u32 len(id) LE ‖ id ‖ version u64 LE ‖ publics ‖ secrets。
    fn canonical(
        id: &str,
        version: u64,
        publics: &[FieldElement],
        secrets: &[FieldElement],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(id.len() as u32).to_le_bytes());
        buf.extend_from_slice(id.as_bytes());
        buf.extend_from_slice(&version.to_le_bytes());
        for fe in publics.iter().chain(secrets.iter()) {
            buf.extend_from_slice(fe.as_bytes());
        }
        buf
    }
}

#[cfg(any(test, feature = "test-util"))]
#[async_trait]
impl ProofProver for TransparentProver {
    async fn prove(
        &self,
        circuit: &CircuitSpec,
        witness: &Witness,
    ) -> Result<ProofBundle, DomainError> {
        let canonical =
            Self::canonical(&circuit.id, circuit.version, &circuit.public_inputs, &witness.secrets);
        let digest = keccak256(&canonical);
        let mut proof = digest.to_vec();
        for s in &witness.secrets {
            proof.extend_from_slice(s.as_bytes());
        }
        Ok(ProofBundle {
            circuit_id: circuit.id.clone(),
            version: circuit.version,
            proof,
            publics: circuit.public_inputs.clone(),
        })
    }

    fn verify(&self, bundle: &ProofBundle) -> Result<bool, DomainError> {
        if bundle.proof.len() < 32 || !(bundle.proof.len() - 32).is_multiple_of(32) {
            return Ok(false);
        }
        let (digest, tail) = bundle.proof.split_at(32);
        let secrets: Vec<FieldElement> = tail
            .chunks_exact(32)
            .map(|c| FieldElement::from_bytes(c.try_into().expect("chunks_exact 保证 32 字节")))
            .collect();
        let canonical =
            Self::canonical(&bundle.circuit_id, bundle.version, &bundle.publics, &secrets);
        Ok(keccak256(&canonical) == digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    /// 极简 block_on（与 vg-domain 测试同款）：内存实现的 future 永远
    /// 就绪；zk crate 不引入 tokio 等运行时依赖。
    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        loop {
            if let std::task::Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }

    fn u32_fe(v: u32) -> FieldElement {
        u32_to_fe(v)
    }

    fn word_fe(word: [u8; 32]) -> FieldElement {
        FieldElement::from_bytes(word)
    }

    /// note_opening 测试见证（6 个前像词）与其公开输入（由
    /// prove_note_opening 的承诺对账，直接用 host 承诺 limb）。
    fn note_case() -> (CircuitSpec, Witness) {
        let parts: Vec<[u8; 32]> = vec![
            [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32],
        ];
        let c = vg_infra_crypto::poseidon::poseidon_note_commitment(&parts);
        let publics: Vec<FieldElement> = (0..8)
            .map(|i| {
                u32_fe(u32::from_le_bytes(
                    c.as_bytes()[4 * i..4 * i + 4].try_into().unwrap(),
                ))
            })
            .collect();
        (
            CircuitSpec {
                id: NOTE_OPENING_CIRCUIT_ID.into(),
                version: NOTE_OPENING_CIRCUIT_VERSION,
                public_inputs: publics,
            },
            Witness {
                secrets: parts.iter().map(|w| word_fe(*w)).collect(),
            },
        )
    }

    /// range_check 测试见证：x = 0x1_0000_1234，salt 0xAB，B = 1<<48。
    fn range_case() -> (CircuitSpec, Witness) {
        let x: u64 = 0x1_0000_1234;
        let salt = [0xABu8; 16];
        let bound: u64 = 1 << 48;
        let parts = crate::circuits::range_check::range_commitment_parts(x, &salt);
        let c = vg_infra_crypto::poseidon::poseidon_note_commitment(&parts);
        let chunk = |j: u32| u32_fe(((bound >> (30 * j)) & 0x3FFF_FFFF) as u32);
        let mut publics = vec![chunk(0), chunk(1), chunk(2)];
        for i in 0..8 {
            publics.push(u32_fe(u32::from_le_bytes(
                c.as_bytes()[4 * i..4 * i + 4].try_into().unwrap(),
            )));
        }
        (
            CircuitSpec {
                id: RANGE_CHECK_CIRCUIT_ID.into(),
                version: RANGE_CHECK_CIRCUIT_VERSION,
                public_inputs: publics,
            },
            Witness {
                secrets: vec![word_fe(parts[0]), word_fe(parts[1])],
            },
        )
    }

    /// coldchain_max 测试见证（黄金读数与上限）。
    fn coldchain_case() -> (CircuitSpec, Witness) {
        let readings: [u32; 8] = [2350, 2400, 2380, 2415, 2390, 2365, 2420, 2375];
        let t_max = 2500u32;
        let root = crate::circuits::coldchain::coldchain_root(&readings);
        let mut publics = vec![u32_fe(t_max)];
        for i in 0..8 {
            publics.push(u32_fe(u32::from_le_bytes(
                root.as_bytes()[4 * i..4 * i + 4].try_into().unwrap(),
            )));
        }
        (
            CircuitSpec {
                id: COLDCHAIN_MAX_CIRCUIT_ID.into(),
                version: COLDCHAIN_MAX_CIRCUIT_VERSION,
                public_inputs: publics,
            },
            Witness {
                secrets: readings.iter().map(|t| u32_fe(*t)).collect(),
            },
        )
    }

    #[test]
    fn dispatcher_routes_all_three_circuits() {
        let d = ProverDispatcher;
        for (spec, witness) in [note_case(), range_case(), coldchain_case()] {
            let bundle = block_on(d.prove(&spec, &witness))
                .unwrap_or_else(|e| panic!("{} 路由 prove 应成功：{e}", spec.id));
            assert_eq!(bundle.circuit_id, spec.id);
            assert_eq!(bundle.version, spec.version);
            assert_eq!(bundle.publics, spec.public_inputs);
            assert!(
                d.verify(&bundle).unwrap_or_else(|e| panic!("{} verify 应成功：{e}", spec.id)),
                "{} 证明 verify 必须 true",
                spec.id
            );
        }
    }

    #[test]
    fn unknown_circuit_or_version_rejected() {
        let d = ProverDispatcher;
        let (spec, witness) = coldchain_case();
        // 未知 id
        let mut bad = spec.clone();
        bad.id = "nonsense".into();
        let err = block_on(d.prove(&bad, &witness)).expect_err("未知 id 必须被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)));
        // 已知 id 但版本不符
        let mut bad = spec.clone();
        bad.version = spec.version + 1;
        let err = block_on(d.prove(&bad, &witness)).expect_err("版本不符必须被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)));
        // verify 侧同样拒绝未知电路
        let bundle = block_on(d.prove(&spec, &witness)).unwrap();
        let mut misrouted = bundle.clone();
        misrouted.circuit_id = "nonsense".into();
        assert!(matches!(
            d.verify(&misrouted),
            Err(DomainError::InvalidInput(_))
        ));
    }

    #[test]
    fn witness_shape_violations_rejected() {
        let d = ProverDispatcher;
        // note_opening：secrets 数量错
        let (mut spec, mut witness) = note_case();
        witness.secrets.pop();
        assert!(matches!(
            block_on(d.prove(&spec, &witness)),
            Err(DomainError::InvalidInput(_))
        ));
        // range_check：secrets 数量错
        let (spec2, mut witness2) = range_case();
        spec = spec2;
        witness2.secrets.pop();
        assert!(matches!(
            block_on(d.prove(&spec, &witness2)),
            Err(DomainError::InvalidInput(_))
        ));
        // coldchain：secrets 数量错 + publics 数量错 + 高位字节非零
        let (spec3, mut witness3) = coldchain_case();
        spec = spec3;
        witness3.secrets.pop();
        assert!(matches!(
            block_on(d.prove(&spec, &witness3)),
            Err(DomainError::InvalidInput(_))
        ));
        let (_, w4) = coldchain_case();
        let mut short_spec = spec.clone();
        short_spec.public_inputs.pop();
        assert!(matches!(
            block_on(d.prove(&short_spec, &w4)),
            Err(DomainError::InvalidInput(_))
        ));
        // 非 u32 装载（高 28 字节非零）
        let (_, mut w5) = coldchain_case();
        let mut raw = [0u8; 32];
        raw[31] = 1;
        w5.secrets[0] = FieldElement::from_bytes(raw);
        assert!(matches!(
            block_on(d.prove(&spec, &w5)),
            Err(DomainError::InvalidInput(_))
        ));
    }

    #[test]
    fn publics_mismatch_rejected() {
        let d = ProverDispatcher;
        let (mut spec, witness) = note_case();
        // 篡改第一个公开 limb（承诺不一致）
        let first = u32_to_fe(0x1234_5678);
        spec.public_inputs[0] = first;
        let err = block_on(d.prove(&spec, &witness))
            .expect_err("公开输入与承诺不一致必须被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)));
    }

    /// 跨电路 proof 喂错 id：同型 config 下 postcard 可互解，但错误
    /// AIR 的约束校验必失败 —— 路由设计的既定行为是 Ok(false)。
    #[test]
    fn cross_circuit_proof_rejected() {
        let d = ProverDispatcher;
        let (spec, witness) = coldchain_case();
        let bundle = block_on(d.prove(&spec, &witness)).unwrap();
        let mut misrouted = bundle.clone();
        misrouted.circuit_id = RANGE_CHECK_CIRCUIT_ID.into();
        misrouted.version = RANGE_CHECK_CIRCUIT_VERSION;
        // publics 数量 9 ≠ range 的 11 → InvalidInput（本路由的第一道拦截）
        assert!(matches!(
            d.verify(&misrouted),
            Err(DomainError::InvalidInput(_))
        ));
        // 补齐 publics 数量后走真实校验 → false
        let mut misrouted = bundle;
        misrouted.circuit_id = RANGE_CHECK_CIRCUIT_ID.into();
        misrouted.version = RANGE_CHECK_CIRCUIT_VERSION;
        misrouted.publics.push(u32_fe(0));
        misrouted.publics.push(u32_fe(0));
        assert!(!d.verify(&misrouted).unwrap_or(false), "跨电路 proof 必须 false");
    }

    #[test]
    fn transparent_prover_roundtrip_and_tamper() {
        let p = TransparentProver;
        let (spec, witness) = coldchain_case();
        let bundle = block_on(p.prove(&spec, &witness)).unwrap();
        assert!(p.verify(&bundle).unwrap(), "回执往返必须 true");
        // 篡改 proof / publics → false
        let mut tampered = bundle.clone();
        tampered.proof[0] ^= 1;
        assert!(!p.verify(&tampered).unwrap());
        let mut tampered = bundle.clone();
        tampered.publics[0] = u32_fe(9999);
        assert!(!p.verify(&tampered).unwrap());
        // 篡改 circuit_id / version → false
        let mut tampered = bundle.clone();
        tampered.version += 1;
        assert!(!p.verify(&tampered).unwrap());
        // 任意 circuit 均可回执（无注册表）
        let mut any = spec.clone();
        any.id = "adhoc".into();
        let bundle2 = block_on(p.prove(&any, &witness)).unwrap();
        assert!(p.verify(&bundle2).unwrap());
        // 过短 proof → false
        let mut short = bundle;
        short.proof.truncate(10);
        assert!(!p.verify(&short).unwrap());
    }

    /// 编译期哨兵：两个实现必须 Send + Sync（服务型端口约定）。
    #[test]
    fn provers_are_send_sync() {
        fn requires_send_sync<T: Send + Sync>(_: &T) {}
        requires_send_sync(&ProverDispatcher);
        requires_send_sync(&TransparentProver);
    }
}
