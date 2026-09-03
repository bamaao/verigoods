//! 隐私侧：Shielded 转移（intent 写）、Note 扫描、监管解密与
//! Private Validium（状态根提交 / 数据访问授权）。
//!
//! - `POST /api/v1/shielded/transfers`：body = 完整 ShieldedTransfer
//!   payload（`subject/old_note/recipient_meta/amount/from_did/to_did/
//!   regulator_view_pub`，契约见 vg-application
//!   `handlers::shielded::ShieldedTransferHandler` doc）+ `intent_id?` /
//!   `on_behalf_of?` → `execute(ShieldedTransfer)`（L3 监管副签审批门）；
//! - `POST /api/v1/shielded/notes/scan`：**敏感端点**（监管/接收方自扫；
//!   Phase1 无 ABAC 强制，Phase2 接 IAM）；
//! - `POST /api/v1/shielded/decrypt`：监管解密。**双因子第二因子
//!   `data_access_grants` 查验在此做**（MEMORY 待办落实）：view_priv
//!   属地（第一因子，body 自证）+ grantee = AuthedDid 且 grant 未过期
//!   （第二因子，查短事务）；无授权 → 403；
//! - `POST /api/v1/validium/roots`：Merkle 状态根提交（系统级结算，
//!   `SubmitStateRoot` 语义，服务层直调）；
//! - `POST /api/v1/validium/grants`：IAM 管理端点（授权数据集访问）。

use axum::extract::State;
use axum::Json;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::Row;
use vg_application::services::shielded::{regulator_decrypt, scan_notes};
use vg_application::services::validium::{grant_data_access, submit_validium_root};
use vg_domain::intent::IntentAction;
use vg_domain::shared::{Did, DomainError, Hash32};

use crate::error::ApiError;
use crate::middleware::auth::AuthedDid;
use crate::routes::{run_intent, split_meta};
use crate::state::SharedState;

/// 监管解密授权的数据集口径（Phase1 写死：ExtraData 密文属单一数据集；
/// Phase2 接 IAM 后按数据集细分）。
const DATASET_SHIELDED_EXTRA: &str = "shielded:extra";

/// Shielded 转移（L3 审批门，首次 execute 停 AwaitingApproval）。
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
        IntentAction::ShieldedTransfer,
        intent_id,
        payload,
    )
    .await
}

/// Note 扫描 body。
#[derive(Debug, serde::Deserialize)]
pub struct ScanBody {
    /// 接收方 view 私钥（64 hex）。
    view_priv: String,
    /// 接收方 spend 公钥（压缩点 hex）。
    spend_pub: String,
}

/// Note 扫描（返回命中 Notes；不返回 spend 私钥本体，见服务 doc）。
pub async fn scan(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(_)): axum::Extension<AuthedDid>,
    crate::AppJson(body): crate::AppJson<ScanBody>,
) -> Result<Json<Value>, ApiError> {
    let notes = scan_notes(state.engine.deps(), &body.view_priv, &body.spend_pub).await?;
    // ScannedNote 无 Serialize：此处显式组装响应（字段口径与服务 doc 一致）
    let items: Vec<Value> = notes
        .into_iter()
        .map(|n| {
            json!({
                "asset_ref": n.asset_ref,
                "amount": n.amount,
                "owner_ot_addr": n.owner_ot_addr,
                "commitment": n.commitment,
                "t": n.t,
            })
        })
        .collect();
    Ok(Json(Value::Array(items)))
}

/// 监管解密 body。
#[derive(Debug, serde::Deserialize)]
pub struct DecryptBody {
    /// ExtraData 密文（base64，标准字母表）。
    extra_base64: String,
    /// 监管 view 私钥（64 hex；第一因子：属地自证）。
    view_priv: String,
}

/// 监管解密（双因子：view_priv 属地 + data_access_grants 未过期授权）。
pub async fn decrypt(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(regulator)): axum::Extension<AuthedDid>,
    crate::AppJson(body): crate::AppJson<DecryptBody>,
) -> Result<Json<Value>, ApiError> {
    // 第二因子：grantee = AuthedDid 且 grant 未过期（now >= until 即失效，
    // 全库过期边界口径一致）——无授权 → 403。
    let until: Option<DateTime<Utc>> = {
        let mut tx = super::begin_tx(&state.pool).await?;
        let row = sqlx::query(
            "SELECT until FROM data_access_grants WHERE grantee = $1 AND dataset = $2 \
             ORDER BY until DESC LIMIT 1",
        )
        .bind(regulator.as_str())
        .bind(DATASET_SHIELDED_EXTRA)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| DomainError::Storage(format!("data_access_grants 读取失败：{e}")))?;
        tx.commit()
            .await
            .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
        row.map(|r| r.get("until"))
    };
    let authorized = until.is_some_and(|u| Utc::now() < u);
    if !authorized {
        return Err(ApiError::from(DomainError::PolicyViolated(format!(
            "无数据访问授权（dataset={DATASET_SHIELDED_EXTRA}）：需先经 IAM 端点授予未过期授权"
        ))));
    }

    // 第一因子 + 密码学解密
    let extra = base64::engine::general_purpose::STANDARD
        .decode(&body.extra_base64)
        .map_err(|e| ApiError::bad_request(format!("extra_base64 解码失败：{e}")))?;
    Ok(Json(regulator_decrypt(&extra, &body.view_priv)?))
}

/// Validium 根提交 body。
#[derive(Debug, serde::Deserialize)]
pub struct RootBody {
    /// 批次引用（幂等键）。
    batch_ref: String,
    /// 条目哈希列表（各 64 hex，`0x` 前缀可选）。
    items: Vec<String>,
}

/// 提交状态根（Merkle(items) → 库 → 账本锚定；**仅 Regulator**，
/// Phase1 粗粒度 kind 校验 → 403，辖区级留 Phase2）。
pub async fn submit_root(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(submitter)): axum::Extension<AuthedDid>,
    crate::AppJson(body): crate::AppJson<RootBody>,
) -> Result<Json<Value>, ApiError> {
    super::require_regulator(&state, &submitter).await?;
    let items: Vec<Hash32> = body
        .items
        .iter()
        .map(|h| Hash32::from_hex(h))
        .collect::<Result<_, _>>()?;
    let root = submit_validium_root(state.engine.deps(), &body.batch_ref, &items).await?;
    Ok(Json(json!({ "root": root.as_hex() })))
}

/// 数据访问授权 body。
#[derive(Debug, serde::Deserialize)]
pub struct GrantBody {
    /// 被授权监管方 DID。
    grantee: Did,
    /// 数据集标识（Phase1 建议统一 `shielded:extra`）。
    dataset: String,
    /// 授权截止时刻。
    until: DateTime<Utc>,
}

/// 授予数据集访问权（IAM 管理；**仅 Regulator**，Phase1 粗粒度 kind
/// 校验 → 403，辖区级留 Phase2；刷新语义见服务 doc）。
pub async fn grant(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(admin)): axum::Extension<AuthedDid>,
    crate::AppJson(body): crate::AppJson<GrantBody>,
) -> Result<Json<Value>, ApiError> {
    super::require_regulator(&state, &admin).await?;
    grant_data_access(
        state.engine.deps(),
        &body.grantee,
        &body.dataset,
        body.until,
    )
    .await?;
    Ok(Json(json!({
        "grantee": body.grantee,
        "dataset": body.dataset,
        "until": body.until,
    })))
}
