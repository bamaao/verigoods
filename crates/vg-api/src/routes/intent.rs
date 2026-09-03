//! 意图轮询与审批。
//!
//! - `GET /api/v1/intents/{id}`：intent 详情（`IntentResult` 轮询的补充
//!   全量视图）。**脱敏（MEMORY 待办落实）**：`action ==
//!   shielded_transfer` 时 payload 的 `old_note.secret` / `old_note.salt`
//!   花费密钥在响应中**擦除**（键删除）——intent 落库明文仅私有 PG
//!   可见，REST 读出口不得透出花费材料；
//! - `POST /api/v1/intents/{id}/approve`：body 可空（非空时须为 JSON
//!   对象，Phase1 忽略内容）；approver = AuthedDid →
//!   `engine.approve`（L3/L4 审批门续跑后半程）→ 200 IntentResult。

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::Value;
use vg_domain::intent::{Intent, IntentAction};
use vg_domain::shared::{DomainError, IntentId};

use crate::error::ApiError;
use crate::middleware::auth::AuthedDid;
use crate::routes::begin_tx;
use crate::state::SharedState;

/// 擦除 shielded intent payload 中的花费密钥（secret/salt 键删除）。
pub(crate) fn sanitize_intent(mut intent: Intent) -> Intent {
    if intent.action == IntentAction::ShieldedTransfer {
        if let Some(note) = intent
            .payload
            .get_mut("old_note")
            .and_then(Value::as_object_mut)
        {
            note.remove("secret");
            note.remove("salt");
        }
    }
    intent
}

/// intent 详情（脱敏后）。
pub async fn get(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<Intent>, ApiError> {
    let mut tx = begin_tx(&state.pool).await?;
    let intent = state
        .engine
        .deps()
        .intents
        .get(&mut tx, &IntentId::new(id.clone()))
        .await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    intent
        .map(sanitize_intent)
        .map(Json)
        .ok_or(ApiError::IntentNotFound(id))
}

/// 审批（L3/L4 停门续跑）。
pub async fn approve(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(approver)): axum::Extension<AuthedDid>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<vg_application::IntentResult>, ApiError> {
    // body 可空；非空时必须为 JSON 对象（Phase1 忽略内容，仅做形状校验）
    if !body.is_empty() {
        let v: Value = serde_json::from_slice(&body)
            .map_err(|e| ApiError::bad_request(format!("请求体 JSON 解析失败：{e}")))?;
        if !v.is_object() {
            return Err(ApiError::bad_request("审批请求体必须为 JSON 对象（或空）"));
        }
    }
    let result = state.engine.approve(&IntentId::new(id), &approver).await?;
    Ok(Json(result))
}
