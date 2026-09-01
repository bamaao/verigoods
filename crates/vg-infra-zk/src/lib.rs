//! # vg-infra-zk：VeriGoods 隐私层 ZK 电路（Plonky3）。
//!
//! 基于 Plonky3 `p3-uni-stark`（0.7.0-rc.1，FRI + STARK）实现真实电路，
//! 当前唯一电路为 [`circuits::note_opening`]：证明「知道某 Poseidon2
//! Note 承诺 C 的前像」。host 侧 sponge 规范的唯一复算依据是
//! `vg_infra_crypto::poseidon` 模块文档（两侧 golden vector 锁定一致）。
//!
//! ## 诚实边界（设计文档既定）
//!
//! 本 crate 的 STARK 配置为 **非零知识**（uni-stark 默认未盲化 trace）：
//! 证明系统保证简洁性与可靠性（soundness），但 proof 会泄露 witness
//! 列的承诺 openings——满足查询路径即可复原前像 limb。Phase 3 切换
//! Shielded Transactions 上链前需改造为盲化配置（HidingFriPcs /
//! MerkleTreeHidingMmcs，见 p3-uni-stark tests 的 zk 配置模板），
//! 对外 API 不变。
//!
//! ## 同步 API
//!
//! 本 crate 只暴露同步证明/验证函数（prove 耗时受 FRI 参数与 trace
//! 高度支配）；Task 13 的 `PlonkyProver` 端口适配层负责包装为 domain
//! 的异步端口并转换为 `ProofBundle`。

pub mod circuits;

pub use circuits::note_opening::{
    prove_note_opening, verify_note_opening, ProofOutput, NOTE_OPENING_CIRCUIT_ID,
    NOTE_OPENING_CIRCUIT_VERSION,
};

/// ZK 电路统一错误。
///
/// 只做粗粒度分类（infra 层不越权映射 HTTP 状态码；如需区分 400/500
/// 由上层映射层处理）。
#[derive(Debug, thiserror::Error)]
pub enum ZkError {
    /// 见证非法：parts 为空、超长等结构问题（防御：不 panic，返回错误）。
    #[error("非法见证：{0}")]
    InvalidWitness(String),
    /// 证明序列化失败。
    #[error("证明序列化失败：{0}")]
    Serialization(String),
}
