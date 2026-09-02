//! 组合根：`AppDeps` 持有全部服务（trait object `Arc<dyn ...>`）。
//!
//! plan 草图中的泛型参数化仅为示意：所有 Pg 仓储的 `Context` 关联类型
//! 统一绑定为 [`PgTx`]（`sqlx::Transaction<'static, Postgres>`），用
//! `dyn Trait + 关联类型绑定` 即可保证事务组合的一致性——具体 Pg 类型
//! 别名足够，不做泛型参数化（少一层到处传染的泛型噪音）。
//!
//! 依赖方向恒为 application → domain/infra；`AppDeps` 在 bootstrap
//! （Task 23）装配一次后 `Arc` 共享（`Clone` 仅复制 Arc 计数）。

use std::sync::Arc;

use vg_domain::commodity::ports::CommodityRepository;
use vg_domain::credential::ports::CredentialRepository;
use vg_domain::identity::ports::IdentityRepository;
use vg_domain::intent::ports::IntentRepository;
use vg_domain::lifecycle::ports::LifecycleRepository;
use vg_domain::ownership::ports::OwnershipRepository;
use vg_domain::policy::ports::PolicyRepository;
use vg_domain::ports::{LedgerPort, NoteHasher, ProofProver};
use vg_infra_pg::{PgApprovalsStore, PgAuditWriter, PgOutbox, PgProofStore};

/// 全体仓储共享的事务上下文类型（infra 各实现的 `Context` 绑定值）。
pub type PgTx = sqlx::Transaction<'static, sqlx::Postgres>;

/// 应用依赖集合（组合根产物）。
#[derive(Clone)]
pub struct AppDeps {
    /// 共享连接池（事务由各服务/引擎按需开启）。
    pub pool: sqlx::PgPool,
    /// 身份聚合（DID 文档 + 能力委托）。
    pub identity: Arc<dyn IdentityRepository<Context = PgTx> + Send + Sync>,
    /// 凭证聚合。
    pub credentials: Arc<dyn CredentialRepository<Context = PgTx> + Send + Sync>,
    /// 商品聚合（产品/批次/单品/谱系）。
    pub commodity: Arc<dyn CommodityRepository<Context = PgTx> + Send + Sync>,
    /// 所有权/保管聚合。
    pub ownership: Arc<dyn OwnershipRepository<Context = PgTx> + Send + Sync>,
    /// 生命周期事件日志。
    pub lifecycle: Arc<dyn LifecycleRepository<Context = PgTx> + Send + Sync>,
    /// 监管域与策略版本。
    pub policies: Arc<dyn PolicyRepository<Context = PgTx> + Send + Sync>,
    /// 意图管道仓储。
    pub intents: Arc<dyn IntentRepository<Context = PgTx> + Send + Sync>,
    /// ZK 证明存档（infra 侧服务，无领域端口）。
    pub proofs: Arc<PgProofStore>,
    /// 审计写入（只增）。
    pub audit: Arc<PgAuditWriter>,
    /// 领域事件 outbox。
    pub outbox: Arc<PgOutbox>,
    /// 审批待办存储（L3/L4 审批门）。
    pub approvals: Arc<PgApprovalsStore>,
    /// 账本端口（Phase1 默认 `InProcessLedger`）。
    pub ledger: Arc<dyn LedgerPort>,
    /// ZK 证明端口（vg-infra-zk 的 `ProverDispatcher`）。
    pub prover: Arc<dyn ProofProver>,
    /// Note 承诺哈希端口。
    pub hasher: Arc<dyn NoteHasher>,
}
