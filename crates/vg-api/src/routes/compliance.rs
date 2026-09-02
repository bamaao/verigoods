//! 合规只读查询。
//!
//! - `GET /api/v1/compliance/{subject}`：`check_compliance` →
//!   `{compliant, missing}`；
//! - `GET /api/v1/compliance/{subject}/required`：
//!   `get_required_credentials` → 必需凭证类型字符串数组。
//!
//! subject 路径参数口径：`batch:<id>` / `asset:<id>`。

use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};
use vg_application::services::compliance::{check_compliance, get_required_credentials};

use crate::error::ApiError;
use crate::routes::parse_subject_param;
use crate::state::SharedState;

/// 合规检查。
pub async fn check(
    State(state): State<SharedState>,
    Path(subject): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let subject = parse_subject_param(&subject)?;
    let report = check_compliance(state.engine.deps(), &subject).await?;
    Ok(Json(json!({
        "compliant": report.compliant,
        "missing": report.missing.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
    })))
}

/// 必需凭证查询。
pub async fn required(
    State(state): State<SharedState>,
    Path(subject): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let subject = parse_subject_param(&subject)?;
    let required = get_required_credentials(state.engine.deps(), &subject).await?;
    Ok(Json(Value::Array(
        required
            .iter()
            .map(|t| Value::String(t.as_str().to_owned()))
            .collect(),
    )))
}
