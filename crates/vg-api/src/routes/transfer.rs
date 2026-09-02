//! 转移与保管。
//!
//! - `POST /api/v1/transfers`：body = `{intent_id?, on_behalf_of?, subject,
//!   to, c2c, lifecycle_to?, custody?}` → `execute(TransferProduct)`；
//! - `POST /api/v1/custody`：body = `{intent_id?, on_behalf_of?, subject,
//!   to, reason, lifecycle_to?}` → `execute(UpdateCustody)`；
//! - `GET /api/v1/transfers?subject=batch:<id>`（query 参数定案为
//!   `subject=batch:<id>` 字符串口径）：`ownership.history` →
//!   TransferRecord 数组（按追加序）。

use axum::extract::{Query, State};
use axum::Json;
use serde_json::Value;
use std::collections::HashMap;
use vg_domain::intent::IntentAction;
use vg_domain::ownership::ports::OwnershipRepository;
use vg_domain::ownership::TransferRecord;
use vg_domain::shared::DomainError;

use crate::error::ApiError;
use crate::middleware::auth::AuthedDid;
use crate::routes::{begin_tx, parse_subject_param, run_intent, split_meta};
use crate::state::SharedState;

/// 公开转移（所有权）。
pub async fn transfer(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(actor)): axum::Extension<AuthedDid>,
    crate::AppJson(body): crate::AppJson<Value>,
) -> Result<axum::Json<vg_application::IntentResult>, ApiError> {
    let (intent_id, on_behalf_of, payload) = split_meta(body)?;
    run_intent(
        &state.engine,
        actor,
        on_behalf_of,
        IntentAction::TransferProduct,
        intent_id,
        payload,
    )
    .await
}

/// 保管更新。
pub async fn custody(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(actor)): axum::Extension<AuthedDid>,
    crate::AppJson(body): crate::AppJson<Value>,
) -> Result<axum::Json<vg_application::IntentResult>, ApiError> {
    let (intent_id, on_behalf_of, payload) = split_meta(body)?;
    run_intent(
        &state.engine,
        actor,
        on_behalf_of,
        IntentAction::UpdateCustody,
        intent_id,
        payload,
    )
    .await
}

/// 转移历史（审计回放）。
pub async fn history(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<TransferRecord>>, ApiError> {
    let raw = params.get("subject").ok_or_else(|| {
        ApiError::bad_request("缺少必填 query 参数 subject（batch:<id> / asset:<id>）")
    })?;
    let subject = parse_subject_param(raw)?;
    let repo = vg_infra_pg::PgOwnershipRepo;
    let mut tx = begin_tx(&state.pool).await?;
    let records = repo.history(&mut tx, &subject).await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    Ok(Json(records))
}
