//! 消费者聚合视图（**免签**——中间件白名单覆盖 `GET /api/v1/consumer/*`）。
//!
//! `GET /api/v1/consumer/{subject}`（subject 口径 `batch:<id>`）：
//! `{subject, state, transfer_count, c2c_count, owner_masked, produced_at,
//! age_days, compliance_ok}`。
//!
//! **脱敏契约**：消费者端点是非授权语义，`owner_masked` 恒脱敏——
//! `"DID-" + DID 后缀（`did:vg:` 之后）前 8 位大写 hex`，任何请求方
//! （含所有者本人）经本端点都只能看到掩码；完整 owner 走签名的
//! `GET /api/v1/batches/{id}`。批次不存在 → 404。
//!
//! Phase1 口径：仅批次（asset 无 produced_at 年龄语义，暂 400）。

use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use serde_json::{json, Value};
use vg_domain::shared::DomainError;

use crate::error::ApiError;
use crate::routes::{begin_tx, parse_subject_param};
use crate::state::SharedState;

/// owner DID 掩码：`DID-` + `did:vg:` 后缀前 8 位（大写）。
pub(crate) fn mask_did(did: &vg_domain::shared::Did) -> String {
    let suffix = did.as_str().strip_prefix("did:vg:").unwrap_or(did.as_str());
    format!(
        "DID-{}",
        suffix.chars().take(8).collect::<String>().to_uppercase()
    )
}

/// 消费者聚合视图。
pub async fn view(
    State(state): State<SharedState>,
    Path(subject): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let subject = parse_subject_param(&subject)?;
    let vg_domain::shared::SubjectRef::Batch(batch_id) = &subject else {
        return Err(ApiError::bad_request(
            "消费者视图 Phase1 仅支持批次（batch:<id>）",
        ));
    };

    let mut tx = begin_tx(&state.pool).await?;
    let batch = state
        .engine
        .deps()
        .commodity
        .find_batch(&mut tx, batch_id)
        .await?
        .ok_or(DomainError::NotFound)?;
    let ownership = state.engine.deps().ownership.get(&mut tx, &subject).await?;
    let state_str = match state
        .engine
        .deps()
        .lifecycle
        .current_state(&mut tx, &subject)
        .await?
    {
        Some(s) => s.as_str().to_owned(),
        // 无事件时回读聚合档案（与 services::compliance::current_state 同源口径）
        None => batch.state.as_str().to_owned(),
    };
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;

    let owner_masked = ownership
        .as_ref()
        .map(|o| mask_did(&o.owner))
        .unwrap_or_else(|| "DID-UNKNOWN".to_owned());
    let age_days = (Utc::now() - batch.produced_at).num_days();

    Ok(Json(json!({
        "subject": format!("batch:{batch_id}"),
        "state": state_str,
        "transfer_count": ownership.as_ref().map(|o| o.transfer_count).unwrap_or(0),
        "c2c_count": ownership.as_ref().map(|o| o.c2c_count).unwrap_or(0),
        "owner_masked": owner_masked,
        "produced_at": batch.produced_at,
        "age_days": age_days,
        "compliance_ok": batch.compliance_ok,
    })))
}
