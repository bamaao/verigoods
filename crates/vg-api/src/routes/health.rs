//! `GET /health` 探活路由。
//!
//! 含 DB ping（`SELECT 1`）：库不可达返回 503（部署侧健康检查依赖）。

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::state::SharedState;

/// 健康检查：DB 可达 200 `{"status":"ok"}`，不可达 503 `{"status":"degraded"}`。
pub async fn health(State(state): State<SharedState>) -> Response {
    let db_ok = sqlx::query("SELECT 1")
        .execute(&state.pool)
        .await
        .is_ok();
    if db_ok {
        (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "degraded" })),
        )
            .into_response()
    }
}
