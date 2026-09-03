//! AlloyLedger：[`LedgerPort`] 的 alloy 实现（Task 26，feature `chain-alloy`）。
//!
//! ## LedgerItem → 合约调用映射表
//!
//! | LedgerItem | 合约调用 | 说明 |
//! |---|---|---|
//! | `Nullifier(nf)` | （暂存，不发 tx） | 等待同批 Commitment/Extra 配对 |
//! | `Commitment(c)` | （暂存，不发 tx） | 同上；无 pending nf 时后续 E 走 fallback |
//! | `EncryptedExtra(extra)` | `commitAndSpend(nf, c, extra)` 原子上链 | N+C 均在；回执 tx_ref 为该真实交易 |
//! | `EncryptedExtra(extra)`（fallback） | `commit(c, extra)` | 仅 C 在（无 pending nf） |
//! | `Transfer` / `CredentialStatus` / `LifecycleChange` / `PolicyRegistered` | **不支持** → `DomainError::Storage` | Phase1 合约范围外（Phase2 扩合约） |
//! | `submit_state_root(root, batch_ref)` | `StateAnchor.commitRoot(root, batchRef)` | 零根由合约 require 拒绝 |
//! | `is_nullifier_spent` / `is_commitment_present` | 视图调用 | 直查合约 mapping |
//!
//! ## 回执语义
//!
//! - 真实上链（Extra 触发的 tx、commitRoot）：`tx_ref = "chain:0x<txhash>"`、
//!   `in_process = false`、`anchored_at = Utc::now()`（本地时间戳，非块时间）。
//! - 暂存（N/C）：`tx_ref = "chain:deferred:<kind>:<hex>"`——**延迟回执**，
//!   指向缓冲意图而非真实交易（真实 tx 由后续 Extra 触发时产生）。
//! - 双花（nf 已花 / commitment 已存）：合约 require revert → 交易上链失败
//!   → `DomainError::Storage`（与 InProcessLedger 幂等返回旧回执的行为
//!   **不同**——链侧如实暴露冲突，重试/幂等归上层，见 lib.rs 错误语义）。

use std::sync::Mutex;

use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::Provider;

use async_trait::async_trait;
use chrono::Utc;
use vg_domain::ports::{AnchorReceipt, LedgerItem, LedgerPort};
use vg_domain::shared::{DomainError, Hash32};

use crate::bindings::{IShieldedRegistry, IStateAnchor};
use crate::pairing::{AnchorPlan, PairingBuffer};

/// alloy 链账本（服务型端口：自管 nonce/重试，无 Context）。
///
/// `P` 为带本地私钥钱包的 HTTP provider 具体类型（由
/// [`ChainConfig::connect`](crate::provider::ChainConfig::connect) 构造，
/// 其返回值已擦除为 `Arc<dyn LedgerPort>`，本泛型只为可测/可注入）。
///
/// 字段 `pairing` 为 N→C→E 顺序契约的配对缓冲（见 lib.rs 大字契约）。
pub struct AlloyLedger<P> {
    /// 带本地私钥钱包的 HTTP provider（Polygon CDK L2 RPC）。
    provider: P,
    /// ShieldedRegistry 合约地址。
    shielded_registry: Address,
    /// StateAnchor 合约地址。
    state_anchor: Address,
    /// N→C→E 配对缓冲（锁中毒视为致命——状态机损坏即报）。
    pairing: Mutex<PairingBuffer>,
}

impl<P> AlloyLedger<P> {
    /// 由已建连 provider 与两合约地址构造。
    pub fn new(provider: P, shielded_registry: Address, state_anchor: Address) -> Self {
        Self {
            provider,
            shielded_registry,
            state_anchor,
            pairing: Mutex::new(PairingBuffer::new()),
        }
    }
}

/// 延迟回执（N/C 暂存用，见模块 doc 回执语义）。
fn deferred_receipt(kind: &str, h: &Hash32) -> AnchorReceipt {
    AnchorReceipt {
        tx_ref: format!("chain:deferred:{kind}:{}", hex::encode(h.as_bytes())),
        anchored_at: Utc::now(),
        in_process: false,
    }
}

/// 交易回执 → 锚定回执（tx_ref 统一 `chain:0x<txhash>` 口径；只取
/// `transaction_hash` 字段——`get_receipt()` 的返回类型是泛型
/// `Network::ReceiptResponse` 关联类型，逐字段手取以避免具名）。
fn receipt_of(tx_hash: B256) -> AnchorReceipt {
    AnchorReceipt {
        tx_ref: format!("chain:{tx_hash}"),
        anchored_at: Utc::now(),
        in_process: false,
    }
}

#[async_trait]
impl<P> LedgerPort for AlloyLedger<P>
where
    P: Provider + Clone + Unpin + 'static,
{
    async fn anchor(&self, item: LedgerItem) -> Result<AnchorReceipt, DomainError> {
        match item {
            LedgerItem::Nullifier(nf) => {
                self.pairing
                    .lock()
                    .expect("配对缓冲锁中毒")
                    .on_nullifier(nf);
                Ok(deferred_receipt("nullifier", &nf))
            }
            LedgerItem::Commitment(c) => {
                self.pairing
                    .lock()
                    .expect("配对缓冲锁中毒")
                    .on_commitment(c);
                Ok(deferred_receipt("commitment", &c))
            }
            LedgerItem::EncryptedExtra(extra) => {
                // 锁内只做纯状态机转移，网络 I/O 在锁外（不持锁发交易）
                let plan = self
                    .pairing
                    .lock()
                    .expect("配对缓冲锁中毒")
                    .on_extra(extra)?;
                match plan {
                    AnchorPlan::CommitAndSpend {
                        nf,
                        commitment,
                        extra,
                    } => {
                        let receipt =
                            IShieldedRegistry::new(self.shielded_registry, &self.provider)
                                .commitAndSpend(
                                    B256::from(*nf.as_bytes()),
                                    B256::from(*commitment.as_bytes()),
                                    Bytes::from(extra),
                                )
                                .send()
                                .await
                                .map_err(|e| {
                                    DomainError::Storage(format!("commitAndSpend 发送失败：{e}"))
                                })?
                                .get_receipt()
                                .await
                                .map_err(|e| {
                                    DomainError::Storage(format!(
                                        "commitAndSpend 上链失败（双花/权限/RPC）：{e}"
                                    ))
                                })?;
                        Ok(receipt_of(receipt.transaction_hash))
                    }
                    AnchorPlan::Commit { commitment, extra } => {
                        let receipt =
                            IShieldedRegistry::new(self.shielded_registry, &self.provider)
                                .commit(B256::from(*commitment.as_bytes()), Bytes::from(extra))
                                .send()
                                .await
                                .map_err(|e| DomainError::Storage(format!("commit 发送失败：{e}")))?
                                .get_receipt()
                                .await
                                .map_err(|e| {
                                    DomainError::Storage(format!(
                                        "commit 上链失败（已存在/权限/RPC）：{e}"
                                    ))
                                })?;
                        Ok(receipt_of(receipt.transaction_hash))
                    }
                }
            }
            // Phase1 合约范围外（映射表见模块 doc）
            other => {
                let kind = match &other {
                    LedgerItem::Transfer { .. } => "transfer",
                    LedgerItem::CredentialStatus { .. } => "credential_status",
                    LedgerItem::LifecycleChange { .. } => "lifecycle_change",
                    LedgerItem::PolicyRegistered { .. } => "policy_registered",
                    _ => unreachable!("前四臂已覆盖其余全部变体"),
                };
                Err(DomainError::Storage(format!(
                    "链适配器暂不支持 kind={kind}（Phase1 合约仅覆盖 shielded/state_root，Phase2 扩合约）"
                )))
            }
        }
    }

    async fn submit_state_root(
        &self,
        root: Hash32,
        batch_ref: &str,
    ) -> Result<AnchorReceipt, DomainError> {
        let receipt = IStateAnchor::new(self.state_anchor, &self.provider)
            .commitRoot(B256::from(*root.as_bytes()), batch_ref.to_owned())
            .send()
            .await
            .map_err(|e| DomainError::Storage(format!("commitRoot 发送失败：{e}")))? // 零根 revert 在此暴露
            .get_receipt()
            .await
            .map_err(|e| DomainError::Storage(format!("commitRoot 上链失败：{e}")))?;
        Ok(receipt_of(receipt.transaction_hash))
    }

    async fn is_nullifier_spent(&self, n: &Hash32) -> Result<bool, DomainError> {
        let spent = IShieldedRegistry::new(self.shielded_registry, &self.provider)
            .isNullifierSpent(B256::from(*n.as_bytes()))
            .call()
            .await
            .map_err(|e| DomainError::Storage(format!("isNullifierSpent 查询失败：{e}")))?;
        Ok(spent)
    }

    async fn is_commitment_present(&self, c: &Hash32) -> Result<bool, DomainError> {
        let present = IShieldedRegistry::new(self.shielded_registry, &self.provider)
            .isCommitmentPresent(B256::from(*c.as_bytes()))
            .call()
            .await
            .map_err(|e| DomainError::Storage(format!("isCommitmentPresent 查询失败：{e}")))?;
        Ok(present)
    }
}

#[cfg(test)]
mod tests {
    //! 集成测试：**全部 `#[ignore]`——需真实 Polygon CDK（kurtosis-cdk）RPC
    //! 与已部署合约**（启用步骤见 lib.rs 模块 doc）。
    //!
    //! 运行：`cargo test -p vg-infra-chain --features chain-alloy -- --ignored`
    use super::*;
    use crate::provider::ChainConfig;
    use std::sync::Arc;

    async fn connect() -> Arc<dyn LedgerPort> {
        ChainConfig::from_env()
            .expect("需设置 CHAIN_RPC_URL/OPERATOR_KEY/SHIELDED_REGISTRY_ADDR/STATE_ANCHOR_ADDR/CHAIN_ID")
            .connect()
            .await
            .expect("需可用的 kurtosis-cdk L2 RPC")
    }

    #[tokio::test]
    #[ignore = "需 Polygon CDK(kurtosis-cdk) RPC"]
    async fn anchor_triple_n_c_e_triggers_commit_and_spend() {
        let ledger = connect().await;
        let nf = Hash32::keccak(b"it-nf-1");
        let c = Hash32::keccak(b"it-c-1");
        assert!(!ledger.is_nullifier_spent(&nf).await.unwrap());
        assert!(!ledger.is_commitment_present(&c).await.unwrap());

        // N→C→E 三连锚：前两个为延迟回执，E 触发真实 commitAndSpend
        let r1 = ledger.anchor(LedgerItem::Nullifier(nf)).await.unwrap();
        assert!(r1.tx_ref.starts_with("chain:deferred:nullifier:"));
        let r2 = ledger.anchor(LedgerItem::Commitment(c)).await.unwrap();
        assert!(r2.tx_ref.starts_with("chain:deferred:commitment:"));
        let r3 = ledger
            .anchor(LedgerItem::EncryptedExtra(vec![0xAA, 0xBB]))
            .await
            .unwrap();
        assert!(r3.tx_ref.starts_with("chain:0x"), "E 触发真实交易");
        assert!(!r3.in_process);

        assert!(ledger.is_nullifier_spent(&nf).await.unwrap());
        assert!(ledger.is_commitment_present(&c).await.unwrap());
    }

    #[tokio::test]
    #[ignore = "需 Polygon CDK(kurtosis-cdk) RPC"]
    async fn double_spend_reverts_as_storage_error() {
        let ledger = connect().await;
        let nf = Hash32::keccak(b"it-nf-2");
        let c1 = Hash32::keccak(b"it-c-2a");
        let c2 = Hash32::keccak(b"it-c-2b");

        // 第一组成功
        ledger.anchor(LedgerItem::Nullifier(nf)).await.unwrap();
        ledger.anchor(LedgerItem::Commitment(c1)).await.unwrap();
        ledger
            .anchor(LedgerItem::EncryptedExtra(vec![1]))
            .await
            .unwrap();

        // 同 nf 双花：合约 require revert → Storage 错误
        ledger.anchor(LedgerItem::Nullifier(nf)).await.unwrap();
        ledger.anchor(LedgerItem::Commitment(c2)).await.unwrap();
        let err = ledger
            .anchor(LedgerItem::EncryptedExtra(vec![2]))
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::Storage(_)),
            "双花应为 Storage：{err:?}"
        );
    }

    #[tokio::test]
    #[ignore = "需 Polygon CDK(kurtosis-cdk) RPC"]
    async fn submit_state_root_is_idempotent_accepted() {
        let ledger = connect().await;
        let root = Hash32::keccak(b"it-root-1");

        // 重复 root 幂等接受（合约不 revert），两次均为真实交易、各自回执
        let r1 = ledger.submit_state_root(root, "it-batch-1").await.unwrap();
        let r2 = ledger.submit_state_root(root, "it-batch-1").await.unwrap();
        assert!(r1.tx_ref.starts_with("chain:0x"));
        assert!(r2.tx_ref.starts_with("chain:0x"));
        assert_ne!(r1.tx_ref, r2.tx_ref);

        // 零根拒绝（合约 require）
        assert!(matches!(
            ledger.submit_state_root(Hash32::ZERO, "zero").await,
            Err(DomainError::Storage(_))
        ));
    }

    #[tokio::test]
    #[ignore = "需 Polygon CDK(kurtosis-cdk) RPC"]
    async fn view_queries_on_random_hashes_are_false() {
        let ledger = connect().await;
        let h = Hash32::keccak(b"it-absent");
        assert!(!ledger.is_nullifier_spent(&h).await.unwrap());
        assert!(!ledger.is_commitment_present(&h).await.unwrap());
    }

    /// 编译期哨兵：实现满足 Send + Sync（服务端口约定；以 RootProvider
    /// 为代表具象化泛型 P）。
    #[test]
    fn alloy_ledger_is_send_sync() {
        fn requires_send_sync<T: Send + Sync>() {}
        fn check<P: Provider + Clone + Unpin + 'static>() {
            requires_send_sync::<AlloyLedger<P>>();
        }
        check::<alloy::providers::RootProvider>();
    }
}
