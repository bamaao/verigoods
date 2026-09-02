//! # vg-api：HTTP API 层（Axum 引导 / VG-SIG 鉴权 / 错误映射）。
//!
//! 模块：
//! - [`config`]：环境变量配置（DATABASE_URL / BIND_ADDR / VG_PROVER）；
//! - [`state`]：共享应用状态（IntentEngine + PgPool + NonceStore）；
//! - [`error`]：领域错误 → HTTP 状态码统一映射；
//! - [`extract`]：`AppJson` 请求体提取器（JSON 解析失败 → 统一 400 错误体）；
//! - [`middleware`]：VG-SIG 请求签名鉴权中间件；
//! - [`routes`]：路由（`/health` 等；Task 24 挂载业务路由）。
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

/// 组装生产 Router：`/health` + VG-SIG 鉴权中间件（Task 24 起业务路由
/// 在此挂载）。main 只做 bootstrap + serve；auth 集成测试复用同一函数。
pub fn build_router(state: state::SharedState) -> axum::Router {
    use axum::middleware::from_fn_with_state;
    use axum::routing::get;

    let router = axum::Router::new().route("/health", get(routes::health::health));

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
