//! 商品域：批次/单品建档（intent 写）、拆分合并、聚合视图与产品档案。
//!
//! - `POST /api/v1/batches`：body = `{intent_id?, on_behalf_of?, subject,
//!   product_id, quantity, unit, target_state?}` → `execute(CreateBatch)`；
//! - `POST /api/v1/batches/{batch_id}/split`：body = `{intent_id?,
//!   on_behalf_of?, children:[{id,quantity}]}`（subject 由路径注入）→
//!   `execute(SplitBatch)`；
//! - `POST /api/v1/batches/{batch_id}/merge`：body = `{intent_id?,
//!   on_behalf_of?, children:[batch_id...], new_batch_id}`（subject =
//!   `Batch(new_batch_id)`，与 handler M2 校验口径一致）→
//!   `execute(MergeBatch)`；
//! - `POST /api/v1/assets`：body = `{intent_id?, on_behalf_of?, subject,
//!   product_id, authenticity_commitment, manufacturer?}` →
//!   `execute(CreateItem)`；
//! - `GET /api/v1/batches/{batch_id}`：聚合视图（batch/lineage/owner/
//!   transfer_count/c2c_count/state，短事务）；
//! - `POST /api/v1/products`：**建档引导操作**（无对应 intent action，
//!   Phase1 直写 `commodity.save_product`）→ 201；
//! - `GET /api/v1/products/{id}`：200/404。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use vg_domain::commodity::ports::CommodityRepository;
use vg_domain::commodity::{Batch, LineageEdge, ProductType};
use vg_domain::intent::IntentAction;
use vg_domain::shared::{BatchId, DomainError, Hash32, ProductId, SubjectRef};

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
pub async fn merge_batch(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(actor)): axum::Extension<AuthedDid>,
    Path(_batch_id): Path<String>,
    crate::AppJson(body): crate::AppJson<Value>,
) -> Result<axum::Json<vg_application::IntentResult>, ApiError> {
    let (intent_id, on_behalf_of, mut payload) = split_meta(body)?;
    // subject = Batch(new_batch_id)：路径 batch_id 仅为路由定位（参与合并
    // 的父批全集以 body.children 为准），业务口径见 handler doc。
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
    if let Some(hex_str) = payload.get("authenticity_commitment").and_then(Value::as_str) {
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

/// 批次聚合视图。
pub async fn get_batch(
    State(state): State<SharedState>,
    Path(batch_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let id = BatchId::new(batch_id);
    let mut tx = begin_tx(&state.pool).await?;
    let batch: Batch = state
        .engine
        .deps()
        .commodity
        .find_batch(&mut tx, &id)
        .await?
        .ok_or(DomainError::NotFound)?;
    let lineage: Vec<LineageEdge> = state
        .engine
        .deps()
        .commodity
        .lineage_of(&mut tx, &id)
        .await?;
    let ownership = state
        .engine
        .deps()
        .ownership
        .get(&mut tx, &vg_domain::shared::SubjectRef::Batch(id.clone()))
        .await?;
    let state_str = match state
        .engine
        .deps()
        .lifecycle
        .current_state(&mut tx, &vg_domain::shared::SubjectRef::Batch(id.clone()))
        .await?
    {
        Some(s) => s.as_str().to_owned(),
        // 无事件时回读聚合档案（与 services::compliance::current_state 同源口径）
        None => batch.state.as_str().to_owned(),
    };
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    Ok(Json(json!({
        "batch": batch,
        "lineage": lineage,
        "owner": ownership.as_ref().map(|o| o.owner.clone()),
        "transfer_count": ownership.as_ref().map(|o| o.transfer_count).unwrap_or(0),
        "c2c_count": ownership.as_ref().map(|o| o.c2c_count).unwrap_or(0),
        "state": state_str,
    })))
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
    let repo = vg_infra_pg::PgCommodityRepo;
    let mut tx = begin_tx(&state.pool).await?;
    repo.save_product(&mut tx, &product).await?;
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
    let repo = vg_infra_pg::PgCommodityRepo;
    let mut tx = begin_tx(&state.pool).await?;
    let product = repo.find_product(&mut tx, &ProductId::new(id)).await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    product.map(Json).ok_or(ApiError::from(DomainError::NotFound))
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
