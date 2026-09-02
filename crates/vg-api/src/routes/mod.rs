//! 路由层：Task 24 全路由（设计 §6 路径表）。
//!
//! handler 契约（控制器定案）：**薄**——组装 payload → 调
//! engine/服务/仓储 → 包响应；业务校验一律在 handler 之下（engine /
//! 领域）。通用约定：
//! - 写操作 execute 的 actor = `AuthedDid`（VG-SIG 签名者）；
//!   `on_behalf_of` 由 body 可选传（Agent 代发口径由 engine 授权段锁定）；
//! - `intent_id`：body 可含（幂等重试键）；缺省服务端 [`IntentId::generate`]
//!   并在响应 `IntentResult.intent_id` 返回；
//! - 请求体一律经 [`AppJson`](crate::AppJson)（统一 400 错误体）；
//! - 写端点 REST body 与 vg-application 各 handler 的 payload JSON Schema
//!   对齐：本层只剥离路由元字段（`intent_id` / `on_behalf_of`）、按路径
//!   注入 `subject` 等，**不重复定义业务校验**；
//! - intent 服务端 nonce：纳秒时钟（actor 维唯一性由引擎 (actor,nonce)
//!   唯一约束兜底，冲突 → 409）；
//! - intent 服务端过期窗口：10 分钟。

pub mod compliance;
pub mod health;
pub mod commodity;
pub mod consumer;
pub mod credentials;
pub mod identity;
pub mod intent;
pub mod policy;
pub mod shielded;
pub mod transfer;

use chrono::{Duration, Utc};
use serde_json::Value;
use vg_application::{IntentEngine, IntentResult, RawIntent};
use vg_domain::intent::IntentAction;
use vg_domain::shared::{Did, DomainError, IntentId, SubjectRef};

use crate::error::ApiError;

/// 服务端组装 intent 的默认有效期（分钟）。
const INTENT_TTL_MINUTES: i64 = 10;

/// 解析 `batch:<id>` / `asset:<id>` 口径的 subject 参数（路径或 query）。
pub(crate) fn parse_subject_param(raw: &str) -> Result<SubjectRef, ApiError> {
    let (kind, id) = raw
        .split_once(':')
        .ok_or_else(|| ApiError::bad_request(format!("subject 参数必须为 `batch:<id>` 或 `asset:<id>` 口径，实际：{raw}")))?;
    match kind {
        "batch" => Ok(SubjectRef::Batch(vg_domain::shared::BatchId::new(id))),
        "asset" => Ok(SubjectRef::Asset(vg_domain::shared::AssetId::new(id))),
        other => Err(ApiError::bad_request(format!(
            "subject 类型必须为 batch/asset，实际：{other}"
        ))),
    }
}

/// 从 REST body 剥离路由元字段（`intent_id` / `on_behalf_of`），
/// 返回 (幂等键, 被代理方, 业务 payload)。剩余部分必须为 JSON object。
pub(crate) fn split_meta(mut body: Value) -> Result<(Option<String>, Option<Did>, Value), ApiError> {
    let obj = body
        .as_object_mut()
        .ok_or_else(|| ApiError::bad_request("请求体必须为 JSON 对象"))?;
    let intent_id = match obj.remove("intent_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s),
        Some(_) => return Err(ApiError::bad_request("intent_id 必须为字符串")),
    };
    let on_behalf_of = match obj.remove("on_behalf_of") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(Did::parse(&s).map_err(ApiError::from)?),
        Some(_) => return Err(ApiError::bad_request("on_behalf_of 必须为 DID 字符串")),
    };
    let payload = Value::Object(std::mem::take(obj));
    Ok((intent_id, on_behalf_of, payload))
}

/// 服务端 intent nonce：纳秒时钟（碰撞概率可忽略，兜底见模块 doc）。
pub(crate) fn fresh_nonce() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or_else(|_| 1)
}

/// 组装 RawIntent 并执行引擎管道，返回 200 IntentResult。
pub(crate) async fn run_intent(
    engine: &IntentEngine,
    actor: Did,
    on_behalf_of: Option<Did>,
    action: IntentAction,
    intent_id: Option<String>,
    payload: Value,
) -> Result<axum::Json<IntentResult>, ApiError> {
    if !payload.is_object() {
        return Err(ApiError::bad_request("业务 payload 必须为 JSON 对象"));
    }
    let raw = RawIntent {
        id: intent_id
            .map(IntentId::new)
            .unwrap_or_else(IntentId::generate),
        action,
        actor,
        on_behalf_of,
        payload,
        nonce: fresh_nonce(),
        expires_at: Utc::now() + Duration::minutes(INTENT_TTL_MINUTES),
    };
    Ok(axum::Json(engine.execute(raw).await?))
}

/// 开启短事务（读侧统一入口：begin 失败折叠为 Storage 错误）。
pub(crate) async fn begin_tx(
    pool: &sqlx::PgPool,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, DomainError> {
    pool.begin()
        .await
        .map_err(|e| DomainError::Storage(format!("事务开启失败：{e}")))
}

/// 管理端点权限守卫（Phase1 粗粒度）：actor 主体类型必须为 Regulator。
///
/// 适用 `POST /api/v1/policies`、`POST /api/v1/validium/grants`、
/// `POST /api/v1/validium/roots`。非 Regulator（含文档缺失，理论上
/// 过不了 VG-SIG 鉴权）一律 [`DomainError::PolicyViolated`] → 403；
/// 辖区级（jurisdiction 精确匹配）留待 Phase2 接 IAM。
pub(crate) async fn require_regulator(
    state: &crate::state::SharedState,
    actor: &Did,
) -> Result<(), ApiError> {
    use vg_domain::identity::SubjectKind;

    let mut tx = begin_tx(&state.pool).await?;
    let doc = state
        .engine
        .deps()
        .identity
        .find_document(&mut tx, actor)
        .await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    let kind = doc
        .map(|d| d.kind)
        .ok_or_else(|| DomainError::PolicyViolated("签名者 DID 文档不存在".into()))?;
    if kind != SubjectKind::Regulator {
        return Err(ApiError::from(DomainError::PolicyViolated(format!(
            "管理端点仅监管方（Regulator）可调用，实际主体类型：{kind:?}"
        ))));
    }
    Ok(())
}
