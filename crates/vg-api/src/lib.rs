//! # vg-api：HTTP API 层（Axum 引导 / VG-SIG 鉴权 / 错误映射）。
//!
//! 模块：
//! - [`config`]：环境变量配置（DATABASE_URL / BIND_ADDR / VG_PROVER）；
//! - [`state`]：共享应用状态（IntentEngine + PgPool + NonceStore）；
//! - [`error`]：领域错误 → HTTP 状态码统一映射；
//! - [`middleware`]：VG-SIG 请求签名鉴权中间件；
//! - [`routes`]：路由（`/health` 等；Task 24 挂载业务路由）。
//!
//! bin（`src/main.rs`）引导顺序：dotenvy（经 [`config::Config::from_env`]）
//! → tracing → PgPool connect + migrate → `AppDeps` 装配 → `IntentEngine`
//! → Router + 鉴权中间件 → serve。

pub mod config;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod state;

pub use config::{Config, ProverKind};
pub use error::ApiError;
pub use middleware::auth::AuthedDid;
pub use state::{AppState, NonceStore};
