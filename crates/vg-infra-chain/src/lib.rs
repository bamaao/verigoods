//! # vg-infra-chain —— 链层 [`LedgerPort`] 的 alloy 适配器（Task 26）。
//!
//! ## feature 门控
//!
//! 全部合金（alloy）代码以 `cfg(feature = "chain-alloy")` 门控，默认关闭：
//! 默认配置（workspace 测试 / 常规开发）**零 alloy 编译成本**，链适配器
//! 代码不参与编译。启用方式：
//!
//! ```text
//! cargo build -p vg-infra-chain --features chain-alloy
//! cargo clippy -p vg-infra-chain --features chain-alloy -- -D warnings
//! ```
//!
//! ## Polygon CDK（kurtosis-cdk）启用步骤
//!
//! 1. WSL 内安装并启动 kurtosis-cdk（得到 L2 RPC 端点与预置有钱账户）；
//! 2. 部署 `contracts-ext/ShieldedRegistry.sol` 与 `StateAnchor.sol`
//!    （OZ v5 由部署环境提供；本仓不装 Foundry、不本地编译）；
//! 3. 用部署交易 calldata 中的合约地址，铸造/导入操作员私钥；
//! 4. 设置环境变量：`CHAIN_RPC_URL` / `OPERATOR_KEY`（0x 前缀 hex 私钥）/
//!    `SHIELDED_REGISTRY_ADDR` / `STATE_ANCHOR_ADDR` / `CHAIN_ID`；
//! 5. 以 `--features chain-alloy`（vg-api 同名 feature 透传）编译运行；
//! 6. 运行 ignored 集成测试（需真实 RPC）：
//!    `cargo test -p vg-infra-chain --features chain-alloy -- --ignored`。
//!
//! vg-api bootstrap 的选择逻辑：feature 开启且 `CHAIN_RPC_URL` 非空时
//! 装配 [`AlloyLedger`](anchor::AlloyLedger)，否则回落默认
//! `InProcessLedger`（vg-infra-pg）。
//!
//! ## 错误语义
//!
//! RPC 不可达 / 交易上链失败 → `DomainError::Storage`。现状：该错误会使
//! handler 直接失败（意图 Rejected），与 InProcessLedger（本地必成功）
//! 行为有差异——**重试包装（pending 挂起 + 后台 try_anchor）归
//! Task 29 / Phase2 引擎增强**，本 crate 只负责把错误如实上报为 Storage。
//!
//! ## anchor 顺序契约（重要）
//!
//! shielded handler 的悬挂锚调用顺序固定为 **Nullifier → Commitment →
//! EncryptedExtra**（见 vg-application handlers/shielded.rs）。合约的原子
//! 入口 `commitAndSpend(nf, commitment, extra)` 需要三者齐备，而
//! [`LedgerPort::anchor`](vg_domain::ports::LedgerPort::anchor) 是单 item
//! 粒度——适配器内部以 [`PairingBuffer`] 状态机按上述顺序契约配对：
//! N/C 只暂存，收到 E 时组装一次 `commitAndSpend` 原子上链。**若上游
//! 调用顺序改变，配对即失效**（fallback：无 pending nf 的 commitment 走
//! 合约独立 `commit` 入口）。

/// 配对缓冲状态机（纯逻辑，默认 feature 下可测——见模块 doc 顺序契约）。
pub mod pairing {
    use vg_domain::shared::{DomainError, Hash32};

    /// 一次配对完成后的上链计划（由 alloy 侧翻译为合约调用）。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AnchorPlan {
        /// 原子组合入口：`commitAndSpend(nf, commitment, extra)`。
        CommitAndSpend {
            /// 待花费 nullifier。
            nf: Hash32,
            /// 新 note 承诺。
            commitment: Hash32,
            /// 监管可解密文。
            extra: Vec<u8>,
        },
        /// 独立落账入口：`commit(commitment, extra)`（fallback，无 pending nf）。
        Commit {
            /// note 承诺。
            commitment: Hash32,
            /// 附加密文。
            extra: Vec<u8>,
        },
    }

    /// N→C→E 三连锚的配对缓冲（`Mutex` 包裹后嵌入 AlloyLedger）。
    ///
    /// **并发契约**：本状态机假定 `anchor` 调用串行（单 IntentEngine
    /// 事务内顺序调用是当前唯一形态）；外层 `Mutex` 只互斥状态转移瞬间，
    /// I/O 窗口无互斥——并发调用行为未定义，Phase2 重试引擎接入前须改
    /// 为 in-flight 标记（见 anchor.rs 模块 doc）。
    ///
    /// 状态转移（顺序契约 N→C→E；异常序容错但不产生半提交）：
    /// - `Nullifier(nf)`：暂存 nf（覆盖旧值），不出计划；
    /// - `Commitment(c)`：暂存 c，不出计划；
    /// - `EncryptedExtra(extra)`：nf 与 c 均在 → 输出
    ///   [`AnchorPlan::CommitAndSpend`] 并清空；仅 c 在 → 输出
    ///   [`AnchorPlan::Commit`] 并清空；均不在 → `DomainError::Storage`
    ///   （extra 无从归属，宁可失败不造半提交）。
    #[derive(Debug, Default, Clone)]
    pub struct PairingBuffer {
        nf: Option<Hash32>,
        commitment: Option<Hash32>,
    }

    impl PairingBuffer {
        /// 构造空缓冲。
        pub fn new() -> Self {
            Self::default()
        }

        /// Nullifier 到达：仅暂存（真实 tx 由后续 Extra 触发）。
        pub fn on_nullifier(&mut self, nf: Hash32) {
            self.nf = Some(nf);
        }

        /// Commitment 到达：仅暂存（同上）。
        pub fn on_commitment(&mut self, commitment: Hash32) {
            self.commitment = Some(commitment);
        }

        /// EncryptedExtra 到达：按配对状态产出上链计划（见模块 doc）。
        ///
        /// 仅在成功产出计划的分支消耗缓冲；错误分支保留现场（nf 继续等待
        /// 后续 C，下一轮 C→E 仍可配对）。
        pub fn on_extra(&mut self, extra: Vec<u8>) -> Result<AnchorPlan, DomainError> {
            match (self.nf.take(), self.commitment.take()) {
                (Some(nf), Some(commitment)) => Ok(AnchorPlan::CommitAndSpend {
                    nf,
                    commitment,
                    extra,
                }),
                (None, Some(commitment)) => Ok(AnchorPlan::Commit { commitment, extra }),
                // 有 nf 无 c：extra 无从归属，报错；nf 放回保留等待后续 C。
                (Some(nf), None) => {
                    self.nf = Some(nf);
                    Err(DomainError::Storage(
                        "EncryptedExtra 到达时仅有 pending nullifier 而无 commitment（顺序契约 N→C→E 被破坏）"
                            .into(),
                    ))
                }
                (None, None) => Err(DomainError::Storage(
                    "EncryptedExtra 无可归属的 commitment/nullifier（顺序契约 N→C→E 被破坏）"
                        .into(),
                )),
            }
        }

        /// 当前 pending 快照（测试 / 诊断用）。
        pub fn pending(&self) -> (Option<Hash32>, Option<Hash32>) {
            (self.nf, self.commitment)
        }
    }
}

#[cfg(feature = "chain-alloy")]
pub mod anchor;
#[cfg(feature = "chain-alloy")]
pub mod bindings;
#[cfg(feature = "chain-alloy")]
pub mod provider;

#[cfg(test)]
mod tests {
    use super::pairing::{AnchorPlan, PairingBuffer};
    use vg_domain::shared::Hash32;

    /// 顺序契约正例：N→C→E 触发原子 CommitAndSpend，缓冲清空。
    #[test]
    fn n_c_e_sequence_pairs_into_commit_and_spend() {
        let nf = Hash32::keccak(b"nf");
        let c = Hash32::keccak(b"c");
        let mut buf = PairingBuffer::new();

        buf.on_nullifier(nf);
        buf.on_commitment(c);
        assert_eq!(buf.pending(), (Some(nf), Some(c)), "N/C 应暂存不出计划");

        let plan = buf.on_extra(vec![1, 2, 3]).unwrap();
        assert_eq!(
            plan,
            AnchorPlan::CommitAndSpend {
                nf,
                commitment: c,
                extra: vec![1, 2, 3]
            }
        );
        assert_eq!(buf.pending(), (None, None), "配对后缓冲清空");
    }

    /// fallback：无 pending nf 的 C→E 走独立 Commit 入口。
    #[test]
    fn c_e_without_nullifier_falls_back_to_commit() {
        let c = Hash32::keccak(b"c2");
        let mut buf = PairingBuffer::new();
        buf.on_commitment(c);
        assert_eq!(
            buf.on_extra(vec![9]).unwrap(),
            AnchorPlan::Commit {
                commitment: c,
                extra: vec![9]
            }
        );
        assert_eq!(buf.pending(), (None, None));
    }

    /// 违反顺序契约：E 先到（无可归属目标）→ Storage 错误，不产半提交。
    #[test]
    fn extra_without_any_pending_is_error() {
        let mut buf = PairingBuffer::new();
        assert!(buf.on_extra(vec![]).is_err());
    }

    /// 违反顺序契约：N→E（缺 C）→ Storage 错误；nf 保留等待后续 C
    /// （下一轮 C→E 仍可配对，验证不丢状态）。
    #[test]
    fn extra_after_nullifier_only_is_error_but_buffer_keeps_nf() {
        let nf = Hash32::keccak(b"nf3");
        let c = Hash32::keccak(b"c3");
        let mut buf = PairingBuffer::new();
        buf.on_nullifier(nf);
        assert!(buf.on_extra(vec![1]).is_err(), "缺 commitment 应报错");
        assert_eq!(
            buf.pending().0,
            Some(nf),
            "nf 应保留（take 仅在成功配对路径）"
        );

        // 补 C→E 后成功配对
        buf.on_commitment(c);
        assert_eq!(
            buf.on_extra(vec![7]).unwrap(),
            AnchorPlan::CommitAndSpend {
                nf,
                commitment: c,
                extra: vec![7]
            }
        );
    }

    /// 连续两组 N→C→E 互不串扰。
    #[test]
    fn consecutive_triples_do_not_interfere() {
        let mut buf = PairingBuffer::new();
        let (nf1, c1) = (Hash32::keccak(b"nf-a"), Hash32::keccak(b"c-a"));
        let (nf2, c2) = (Hash32::keccak(b"nf-b"), Hash32::keccak(b"c-b"));

        buf.on_nullifier(nf1);
        buf.on_commitment(c1);
        assert_eq!(
            buf.on_extra(vec![1]).unwrap(),
            AnchorPlan::CommitAndSpend {
                nf: nf1,
                commitment: c1,
                extra: vec![1]
            }
        );

        buf.on_nullifier(nf2);
        buf.on_commitment(c2);
        assert_eq!(
            buf.on_extra(vec![2]).unwrap(),
            AnchorPlan::CommitAndSpend {
                nf: nf2,
                commitment: c2,
                extra: vec![2]
            }
        );
    }
}
