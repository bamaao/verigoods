//! vg-api bin：bootstrap 顺序（plan 定案）：
//! dotenvy（经 `Config::from_env`）→ tracing → PgPool connect + migrate
//! → `AppDeps` 装配（按 `VG_PROVER` 选 Prover）→ `IntentEngine`
//! → Router + VG-SIG 中间件 → serve（BIND_ADDR，ctrl-c 优雅关停）。

use std::sync::Arc;

use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum::Router;
use tracing_subscriber::EnvFilter;

use vg_api::config::{Config, ProverKind};
use vg_api::middleware::auth::vg_sig_auth;
use vg_api::routes::health;
use vg_api::state::{AppState, SharedState};
use vg_application::{AppDeps, HandlerMap, IntentEngine};
use vg_infra_pg::{
    PgApprovalsStore, PgAuditWriter, PgCommodityRepo, PgCredentialRepo, PgIdentityRepo,
    PgIntentRepository, PgLifecycleRepo, PgOutbox, PgOwnershipRepo, PgPolicyRepository,
    PgProofStore,
};

#[tokio::main]
async fn main() {
    // 配置（内含 dotenvy 加载）；失败直接 panic——启动参数错误无法恢复
    let config = Config::from_env().unwrap_or_else(|e| panic!("{e}"));

    // tracing：RUST_LOG 优先，默认 info
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    // PgPool connect + migrate（bootstrap 时点一次性应用全部迁移）
    let pool = vg_infra_pg::pool::connect(&config.database_url)
        .await
        .unwrap_or_else(|e| panic!("数据库连接失败：{e}"));
    vg_infra_pg::migrate(&pool)
        .await
        .unwrap_or_else(|e| panic!("数据库迁移失败：{e}"));
    tracing::info!(%config.bind_addr, ?config.prover, "数据库就绪，迁移已应用");

    // AppDeps 装配（组合根）
    let prover: Arc<dyn vg_domain::ports::ProofProver> = match config.prover {
        ProverKind::Plonky => Arc::new(vg_infra_zk::ProverDispatcher),
        #[cfg(feature = "transparent")]
        ProverKind::Transparent => Arc::new(vg_infra_zk::TransparentProver),
        #[cfg(not(feature = "transparent"))]
        ProverKind::Transparent => {
            panic!("VG_PROVER=transparent 需以 `--features transparent` 编译")
        }
    };
    let deps = AppDeps {
        pool: pool.clone(),
        identity: Arc::new(PgIdentityRepo),
        credentials: Arc::new(PgCredentialRepo),
        commodity: Arc::new(PgCommodityRepo),
        ownership: Arc::new(PgOwnershipRepo),
        lifecycle: Arc::new(PgLifecycleRepo),
        policies: Arc::new(PgPolicyRepository),
        intents: Arc::new(PgIntentRepository),
        proofs: Arc::new(PgProofStore),
        audit: Arc::new(PgAuditWriter),
        outbox: Arc::new(PgOutbox),
        approvals: Arc::new(PgApprovalsStore),
        ledger: Arc::new(vg_infra_pg::InProcessLedger::new(pool.clone())),
        prover,
        hasher: Arc::new(vg_infra_crypto::PoseidonNoteHasher),
    };
    let mut handlers = HandlerMap::new();
    vg_application::register_default(&mut handlers);
    let engine = IntentEngine::new(deps, handlers);

    // 共享状态 + 路由
    let state: SharedState = Arc::new(AppState {
        engine,
        pool,
        nonce_store: vg_api::NonceStore::new(),
    });
    let app = Router::new()
        .route("/health", get(health::health))
        // Task 24：业务路由（/api/v1/*）在此挂载（engine 经 state 注入）
        .layer(from_fn_with_state(state.clone(), vg_sig_auth))
        .with_state(state);

    // serve + ctrl-c 优雅关停
    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .unwrap_or_else(|e| panic!("监听 {bind} 失败：{e}", bind = config.bind_addr));
    tracing::info!(addr = %config.bind_addr, "vg-api 已启动");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("收到 ctrl-c，开始优雅关停");
        })
        .await
        .unwrap_or_else(|e| panic!("服务异常退出：{e}"));
}
