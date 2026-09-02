//! # vg-api：HTTP API 层（Axum 引导 / VG-SIG 鉴权 / 错误映射）。
//!
//! 模块：
//! - [`config`]：环境变量配置（DATABASE_URL / BIND_ADDR / VG_PROVER）；
//! - [`state`]：共享应用状态（IntentEngine + PgPool + NonceStore）；
//! - [`error`]：领域错误 → HTTP 状态码统一映射；
//! - [`extract`]：`AppJson` 请求体提取器（JSON 解析失败 → 统一 400 错误体）；
//! - [`middleware`]：VG-SIG 请求签名鉴权中间件；
//! - [`routes`]：路由（`/health` + Task 24 业务路由全集）。
//!
//! bin（`src/main.rs`）引导顺序：dotenvy（经 [`config::Config::from_env`]）
//! → tracing → PgPool connect + migrate → `AppDeps` 装配 → `IntentEngine`
//! → Router + 鉴权中间件 → serve。

pub mod config;
pub mod error;
pub mod extract;
pub mod middleware;
pub mod routes;
pub mod state;

pub use config::{Config, ProverKind};
pub use error::ApiError;
pub use extract::AppJson;
pub use middleware::auth::AuthedDid;
pub use state::{AppState, NonceStore};

/// 组装生产 Router：`/health` + `/api/v1` 业务路由全集 + VG-SIG 鉴权
/// 中间件。main 只做 bootstrap + serve；auth 集成测试复用同一函数。
///
/// 鉴权矩阵：除 `GET /api/v1/consumer/*`（免签）与
/// `POST /api/v1/dids`（引导直写）外全部需 VG-SIG 签名（白名单见
/// `middleware::auth`）。
pub fn build_router(state: state::SharedState) -> axum::Router {
    use axum::middleware::from_fn_with_state;
    use axum::routing::{get, post};

    let router = axum::Router::new()
        .route("/health", get(routes::health::health))
        // ---- 身份（注册免签引导，查询需签） ----
        .route("/api/v1/dids", post(routes::identity::register))
        .route("/api/v1/dids/{did}", get(routes::identity::get))
        // ---- 凭证 ----
        .route(
            "/api/v1/credentials",
            post(routes::credentials::issue).get(routes::credentials::list),
        )
        .route(
            "/api/v1/credentials/{credential_id}/revoke",
            post(routes::credentials::revoke),
        )
        // ---- 商品：批次/单品/产品 ----
        .route("/api/v1/batches", post(routes::commodity::create_batch))
        .route("/api/v1/batches/{batch_id}", get(routes::commodity::get_batch))
        .route(
            "/api/v1/batches/{batch_id}/split",
            post(routes::commodity::split_batch),
        )
        .route(
            "/api/v1/batches/{batch_id}/merge",
            post(routes::commodity::merge_batch),
        )
        .route("/api/v1/assets", post(routes::commodity::create_item))
        .route("/api/v1/products", post(routes::commodity::create_product))
        .route("/api/v1/products/{id}", get(routes::commodity::get_product))
        // ---- 转移/保管 ----
        .route(
            "/api/v1/transfers",
            post(routes::transfer::transfer).get(routes::transfer::history),
        )
        .route("/api/v1/custody", post(routes::transfer::custody))
        // ---- 隐私：Shielded + Validium ----
        .route("/api/v1/shielded/transfers", post(routes::shielded::transfer))
        .route("/api/v1/shielded/notes/scan", post(routes::shielded::scan))
        .route("/api/v1/shielded/decrypt", post(routes::shielded::decrypt))
        .route("/api/v1/validium/roots", post(routes::shielded::submit_root))
        .route("/api/v1/validium/grants", post(routes::shielded::grant))
        // ---- 合规 ----
        .route("/api/v1/compliance/{subject}", get(routes::compliance::check))
        .route(
            "/api/v1/compliance/{subject}/required",
            get(routes::compliance::required),
        )
        // ---- 策略 ----
        .route(
            "/api/v1/policies",
            post(routes::policy::create).get(routes::policy::list),
        )
        .route(
            "/api/v1/policies/{id}/{version}",
            get(routes::policy::get),
        )
        // ---- 消费者（GET 免签，脱敏聚合视图） ----
        .route("/api/v1/consumer/{subject}", get(routes::consumer::view))
        // ---- 意图（轮询 + 审批） ----
        .route("/api/v1/intents/{id}", get(routes::intent::get))
        .route(
            "/api/v1/intents/{id}/approve",
            post(routes::intent::approve),
        );

    // 测试保护路由（只随 `cargo test` 编译，不进生产二进制）：
    // - `__test_protected`：回显 AuthedDid，验证签名注入；
    // - `consumer/x`：验证 consumer 段白名单（GET 免签 / POST 需签）。
    #[cfg(test)]
    let router = router
        .route(
            "/api/v1/__test_protected",
            get(|axum::Extension(AuthedDid(did)): axum::Extension<AuthedDid>| async move {
                axum::Json(serde_json::json!({ "did": did.as_str() }))
            }),
        )
        .route(
            "/api/v1/consumer/x",
            get(|| async { "ok" }).post(|| async { "ok" }),
        );

    router
        .layer(from_fn_with_state(
            state.clone(),
            middleware::auth::vg_sig_auth,
        ))
        .with_state(state)
}
