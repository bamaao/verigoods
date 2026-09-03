//! 商品域：批次/单品建档（intent 写）、拆分合并、聚合视图与产品档案。
//!
//! - `POST /api/v1/batches`：body = `{intent_id?, on_behalf_of?, subject,
//!   product_id, quantity, unit, target_state?}` → `execute(CreateBatch)`；
//! - `POST /api/v1/batches/{batch_id}/split`：body = `{intent_id?,
//!   on_behalf_of?, children:[{id,quantity}]}`（subject 由路径注入）→
//!   `execute(SplitBatch)`；
//! - `POST /api/v1/batches/{batch_id}/merge`：body = `{intent_id?,
//!   on_behalf_of?, children:[batch_id...], new_batch_id}`（subject =
//!   `Batch(new_batch_id)`，与 handler M2 校验口径一致；**路径 batch_id
//!   必须属于 body.children**，否则 400——消除"路径参数形同虚设"的
//!   API 歧义）→ `execute(MergeBatch)`；
//! - `POST /api/v1/assets`：body = `{intent_id?, on_behalf_of?, subject,
//!   product_id, authenticity_commitment, manufacturer?}` →
//!   `execute(CreateItem)`；
//! - `GET /api/v1/batches/{batch_id}`：聚合视图（batch/lineage/owner/
//!   transfer_count/c2c_count/state，短事务）；
//! - `POST /api/v1/products`：**建档引导操作**（无对应 intent action，
//!   Phase1 直写 `commodity.save_product`；控制器追认：建档引导操作
//!   走 VG-SIG 直写，Phase2 可改 IntentAction）→ 201；
//! - `GET /api/v1/products/{id}`：200/404。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use vg_domain::commodity::{Batch, LineageEdge, ProductType};
use vg_domain::intent::IntentAction;
use vg_domain::shared::{BatchId, DomainError, Hash32, ProductId, SubjectRef};

use vg_application::{AppDeps, PgTx};

use crate::error::ApiError;
use crate::middleware::auth::AuthedDid;
use crate::routes::{begin_tx, run_intent, split_meta};
use crate::state::SharedState;

/// 建批次。
pub async fn create_batch(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(actor)): axum::Extension<AuthedDid>,
    crate::AppJson(body): crate::AppJson<Value>,
) -> Result<axum::Json<vg_application::IntentResult>, ApiError> {
    let (intent_id, on_behalf_of, payload) = split_meta(body)?;
    run_intent(
        &state.engine,
        actor,
        on_behalf_of,
        IntentAction::CreateBatch,
        intent_id,
        payload,
    )
    .await
}

/// 拆分批次（subject 由路径注入）。
pub async fn split_batch(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(actor)): axum::Extension<AuthedDid>,
    Path(batch_id): Path<String>,
    crate::AppJson(body): crate::AppJson<Value>,
) -> Result<axum::Json<vg_application::IntentResult>, ApiError> {
    let (intent_id, on_behalf_of, mut payload) = split_meta(body)?;
    inject_subject(&mut payload, SubjectRef::Batch(BatchId::new(batch_id)));
    run_intent(
        &state.engine,
        actor,
        on_behalf_of,
        IntentAction::SplitBatch,
        intent_id,
        payload,
    )
    .await
}

/// 合并批次（subject 指向合并产物新批，与 handler M2 校验一致）。
///
/// 路径 `batch_id` 必须属于 `body.children`（消除 API 歧义：路径参数
/// 不是任意命名空间定位，而是参与合并的父批之一），否则 400。
pub async fn merge_batch(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(actor)): axum::Extension<AuthedDid>,
    Path(batch_id): Path<String>,
    crate::AppJson(body): crate::AppJson<Value>,
) -> Result<axum::Json<vg_application::IntentResult>, ApiError> {
    let (intent_id, on_behalf_of, mut payload) = split_meta(body)?;
    // 路径 batch_id 必须出现在 children 中（消除路径参数形同虚设的歧义）
    let in_children = payload
        .get("children")
        .and_then(Value::as_array)
        .is_some_and(|arr| arr.iter().any(|c| c.as_str() == Some(&batch_id)));
    if !in_children {
        return Err(ApiError::bad_request(
            "路径 batch_id 必须是 body.children 中的父批之一（消除 API 歧义）",
        ));
    }
    // subject = Batch(new_batch_id)：合并产物新批为业务主体，
    // 参与合并的父批全集以 body.children 为准，业务口径见 handler doc。
    let new_batch_id = payload
        .get("new_batch_id")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("payload 缺少 new_batch_id 字段"))?
        .to_owned();
    inject_subject(&mut payload, SubjectRef::Batch(BatchId::new(new_batch_id)));
    run_intent(
        &state.engine,
        actor,
        on_behalf_of,
        IntentAction::MergeBatch,
        intent_id,
        payload,
    )
    .await
}

/// 建单品（authenticity_commitment 为 32 字节 hex）。
pub async fn create_item(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(actor)): axum::Extension<AuthedDid>,
    crate::AppJson(body): crate::AppJson<Value>,
) -> Result<axum::Json<vg_application::IntentResult>, ApiError> {
    let (intent_id, on_behalf_of, payload) = split_meta(body)?;
    // 提前校验 hex 形状：避免好形状错误走完整 intent 管道后才被拒
    if let Some(hex_str) = payload
        .get("authenticity_commitment")
        .and_then(Value::as_str)
    {
        Hash32::from_hex(hex_str)?;
    }
    run_intent(
        &state.engine,
        actor,
        on_behalf_of,
        IntentAction::CreateItem,
        intent_id,
        payload,
    )
    .await
}

/// 批次聚合视图组装（唯一口径：REST `GET /batches/{id}`、MCP
/// `mcp_get_batch` 工具与 `commodity://batch/{id}` 资源三方共用）。
///
/// 在调用方提供的读事务内完成全部读取并返回聚合 JSON；事务的
/// commit 由调用方负责（保持各自错误口径）。
pub(crate) async fn batch_aggregate(
    deps: &AppDeps,
    tx: &mut PgTx,
    id: &BatchId,
) -> Result<Value, DomainError> {
    let batch: Batch = deps
        .commodity
        .find_batch(tx, id)
        .await?
        .ok_or(DomainError::NotFound)?;
    let lineage: Vec<LineageEdge> = deps.commodity.lineage_of(tx, id).await?;
    let ownership = deps
        .ownership
        .get(tx, &SubjectRef::Batch(id.clone()))
        .await?;
    let state_str = match deps
        .lifecycle
        .current_state(tx, &SubjectRef::Batch(id.clone()))
        .await?
    {
        Some(s) => s.as_str().to_owned(),
        // 无事件时回读聚合档案（与 services::compliance::current_state 同源口径）
        None => batch.state.as_str().to_owned(),
    };
    Ok(json!({
        "batch": batch,
        "lineage": lineage,
        "owner": ownership.as_ref().map(|o| o.owner.clone()),
        "transfer_count": ownership.as_ref().map(|o| o.transfer_count).unwrap_or(0),
        "c2c_count": ownership.as_ref().map(|o| o.c2c_count).unwrap_or(0),
        "state": state_str,
    }))
}

/// 批次聚合视图。
pub async fn get_batch(
    State(state): State<SharedState>,
    Path(batch_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id = BatchId::new(batch_id);
    let mut tx = begin_tx(&state.pool).await?;
    let value = batch_aggregate(state.engine.deps(), &mut tx, &id).await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    Ok(Json(value))
}

/// 产品建档（引导直写，无 intent action）。
pub async fn create_product(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(_actor)): axum::Extension<AuthedDid>,
    crate::AppJson(body): crate::AppJson<CreateProductBody>,
) -> Result<(StatusCode, Json<ProductType>), ApiError> {
    let product = ProductType::new(
        ProductId::new(body.product_id),
        body.category,
        Hash32::from_hex(&body.metadata_hash)?,
    )?;
    let mut tx = begin_tx(&state.pool).await?;
    state
        .engine
        .deps()
        .commodity
        .save_product(&mut tx, &product)
        .await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    Ok((StatusCode::CREATED, Json(product)))
}

/// 产品查询。
pub async fn get_product(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<ProductType>, ApiError> {
    let mut tx = begin_tx(&state.pool).await?;
    let product = state
        .engine
        .deps()
        .commodity
        .find_product(&mut tx, &ProductId::new(id))
        .await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    product
        .map(Json)
        .ok_or(ApiError::from(DomainError::NotFound))
}

/// 产品建档 body。
#[derive(Debug, serde::Deserialize)]
pub struct CreateProductBody {
    /// 商品标识符。
    product_id: String,
    /// 类目（非空，领域校验）。
    category: String,
    /// 元数据哈希承诺（64 hex，`0x` 前缀可选）。
    metadata_hash: String,
}

/// 向 payload 注入 subject（覆盖或新增；路径口径优先）。
fn inject_subject(payload: &mut Value, subject: vg_domain::shared::SubjectRef) {
    if let Some(obj) = payload.as_object_mut() {
        obj.insert(
            "subject".into(),
            serde_json::to_value(subject).expect("SubjectRef 序列化不可失败"),
        );
    }
}
