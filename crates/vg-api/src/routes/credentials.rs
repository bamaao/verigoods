//! 凭证：签发 / 撤销（写走 intent 管道）与按主体查询。
//!
//! - `POST /api/v1/credentials`：body = `{intent_id?, on_behalf_of?,
//!   subject, holder, ctype, claims, expires_at?, credential_id?,
//!   domain_id?}` → `execute(IssueCredential)`；payload 契约见
//!   vg-application `handlers::credential::IssueCredentialHandler` doc。
//! - `POST /api/v1/credentials/{credential_id}/revoke`：body =
//!   `{intent_id?, on_behalf_of?, subject, reason?}`（credential_id 由
//!   路径注入 payload）→ `execute(RevokeCredential)`。
//! - `GET /api/v1/credentials?subject={did}`：list_by_subject（短事务）；
//!   VC 序列化含 claims 与 credential_hash（hex）。

use axum::extract::{Path, Query, State};
use axum::Json;
use serde_json::Value;
use std::collections::HashMap;
use vg_domain::credential::VerifiableCredential;
use vg_domain::intent::IntentAction;
use vg_domain::shared::{Did, DomainError};

use crate::error::ApiError;
use crate::middleware::auth::AuthedDid;
use crate::routes::{begin_tx, run_intent, split_meta};
use crate::state::SharedState;

/// 签发凭证（IntentResult 200）。
pub async fn issue(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(actor)): axum::Extension<AuthedDid>,
    crate::AppJson(body): crate::AppJson<Value>,
) -> Result<axum::Json<vg_application::IntentResult>, ApiError> {
    let (intent_id, on_behalf_of, payload) = split_meta(body)?;
    ensure_subject(&payload)?;
    run_intent(
        &state.engine,
        actor,
        on_behalf_of,
        IntentAction::IssueCredential,
        intent_id,
        payload,
    )
    .await
}

/// 撤销凭证（credential_id 由路径注入）。
pub async fn revoke(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(actor)): axum::Extension<AuthedDid>,
    Path(credential_id): Path<String>,
    crate::AppJson(body): crate::AppJson<Value>,
) -> Result<axum::Json<vg_application::IntentResult>, ApiError> {
    let (intent_id, on_behalf_of, mut payload) = split_meta(body)?;
    ensure_subject(&payload)?;
    let obj = payload
        .as_object_mut()
        .expect("split_meta 已保证 payload 为对象");
    obj.insert("credential_id".into(), Value::String(credential_id));
    run_intent(
        &state.engine,
        actor,
        on_behalf_of,
        IntentAction::RevokeCredential,
        intent_id,
        payload,
    )
    .await
}

/// 按主体列出凭证（含 claims 与 credential_hash hex）。
pub async fn list(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<VerifiableCredential>>, ApiError> {
    let raw = params
        .get("subject")
        .ok_or_else(|| ApiError::bad_request("缺少必填 query 参数 subject（DID）"))?;
    let did = Did::parse(raw)?;
    let mut tx = begin_tx(&state.pool).await?;
    let vcs = state
        .engine
        .deps()
        .credentials
        .list_by_subject(&mut tx, &did)
        .await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    Ok(Json(vcs))
}

/// payload 必须含 subject（审计资源兜底，engine 拒绝路径依赖）。
fn ensure_subject(payload: &Value) -> Result<(), ApiError> {
    if payload.get("subject").is_some() {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "payload 缺少 subject 字段（{type,id} 对象，审计资源兜底）",
        ))
    }
}
