//! 链连接配置与 provider 构造（Task 26，feature `chain-alloy`）。

use std::str::FromStr;
use std::sync::Arc;

use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use vg_domain::ports::LedgerPort;
use vg_domain::shared::DomainError;

use crate::anchor::AlloyLedger;

/// 链连接配置（Polygon CDK / 任意 EVM 兼容 L2）。
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// L2 RPC 端点（如 kurtosis-cdk 输出的 zkevm-node RPC）。
    pub rpc_url: String,
    /// 操作员私钥（0x 前缀 32 字节 hex，需持有 SHIELDED_OPERATOR_ROLE /
    /// STATE_ANCHOR_OPERATOR_ROLE）。
    pub operator_key: String,
    /// ShieldedRegistry 合约地址。
    pub shielded_registry: Address,
    /// StateAnchor 合约地址。
    pub state_anchor: Address,
    /// 期望链 ID（连接后校验，防配错网络）。
    pub chain_id: u64,
}

impl ChainConfig {
    /// 从环境变量构造：
    /// `CHAIN_RPC_URL` / `OPERATOR_KEY` / `SHIELDED_REGISTRY_ADDR` /
    /// `STATE_ANCHOR_ADDR` / `CHAIN_ID`（均必填，缺失即配置错误）。
    pub fn from_env() -> Result<Self, DomainError> {
        let miss = |k: &str| DomainError::Storage(format!("链配置缺失环境变量 {k}"));
        let rpc_url = std::env::var("CHAIN_RPC_URL").map_err(|_| miss("CHAIN_RPC_URL"))?;
        let operator_key = std::env::var("OPERATOR_KEY").map_err(|_| miss("OPERATOR_KEY"))?;
        let reg =
            std::env::var("SHIELDED_REGISTRY_ADDR").map_err(|_| miss("SHIELDED_REGISTRY_ADDR"))?;
        let anchor = std::env::var("STATE_ANCHOR_ADDR").map_err(|_| miss("STATE_ANCHOR_ADDR"))?;
        let chain_id = std::env::var("CHAIN_ID")
            .map_err(|_| miss("CHAIN_ID"))?
            .parse::<u64>()
            .map_err(|e| DomainError::Storage(format!("CHAIN_ID 解析失败：{e}")))?;

        let shielded_registry = reg
            .parse::<Address>()
            .map_err(|e| DomainError::Storage(format!("SHIELDED_REGISTRY_ADDR 非法：{e}")))?;
        let state_anchor = anchor
            .parse::<Address>()
            .map_err(|e| DomainError::Storage(format!("STATE_ANCHOR_ADDR 非法：{e}")))?;
        Ok(Self {
            rpc_url,
            operator_key,
            shielded_registry,
            state_anchor,
            chain_id,
        })
    }

    /// 建连：本地私钥签名钱包 + HTTP provider，**校验链 ID**（不匹配即
    /// Storage 错误——防指向错误网络后把操作员交易发到别的链）。
    ///
    /// 返回 `Arc<dyn LedgerPort>`（wallet provider 具体类型经 trait 对象
    /// 擦除，直接注入 vg-api bootstrap 的 `AppDeps::ledger`）。
    pub async fn connect(self) -> Result<Arc<dyn LedgerPort>, DomainError> {
        let signer = PrivateKeySigner::from_str(&self.operator_key)
            .map_err(|e| DomainError::Storage(format!("OPERATOR_KEY 私钥解析失败：{e}")))?;

        // ProviderBuilder::new() 已含 Ethereum 推荐填料（gas/nonce/chain-id），
        // wallet 注入本地私钥签名；connect 按协议自动选择传输（http:// → reqwest）。
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect(&self.rpc_url)
            .await
            .map_err(|e| DomainError::Storage(format!("链 RPC 建连失败（{e}）")))?;

        let actual = provider
            .get_chain_id()
            .await
            .map_err(|e| DomainError::Storage(format!("链 RPC 不可达（{e}）")))?;
        if actual != self.chain_id {
            return Err(DomainError::Storage(format!(
                "链 ID 不匹配：期望 {}，实际 {}（检查 CHAIN_RPC_URL / CHAIN_ID）",
                self.chain_id, actual
            )));
        }
        tracing::info!(
            registry = %self.shielded_registry,
            anchor = %self.state_anchor,
            chain_id = actual,
            "alloy 链适配器已连接"
        );
        Ok(Arc::new(AlloyLedger::new(
            provider,
            self.shielded_registry,
            self.state_anchor,
        )))
    }
}
