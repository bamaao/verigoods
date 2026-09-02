//! DID 注册与查询。
//!
//! - `POST /api/v1/dids`：**引导操作**（新主体尚无签名者，Phase1 免签直写
//!   ——中间件白名单放行；actor 合法性属颁发流程外的治理问题，Phase2
//!   引入注册审批后收紧）。首次创建 201；重复注册按 upsert 语义 200。
//! - `GET /api/v1/dids/{did}`：查询文档（VG-SIG 签名），404 未知 DID。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use vg_domain::identity::ports::IdentityRepository;
use vg_domain::identity::DidDocument;
use vg_domain::shared::{Did, DomainError};

use crate::error::ApiError;
use crate::routes::begin_tx;
use crate::state::SharedState;

/// 注册（upsert）DID 文档：首次 201，重复 200。
pub async fn register(
    State(state): State<SharedState>,
    crate::AppJson(doc): crate::AppJson<DidDocument>,
) -> Result<(StatusCode, Json<DidDocument>), ApiError> {
    let repo = vg_infra_pg::PgIdentityRepo;
    let mut tx = begin_tx(&state.pool).await?;
    let existing = repo.find_document(&mut tx, &doc.did).await?;
    // save_document 为 upsert 语义（幂等重放安全）
    repo.save_document(&mut tx, &doc).await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    let status = if existing.is_some() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(doc)))
}

/// 查询 DID 文档。
pub async fn get(
    State(state): State<SharedState>,
    Path(did): Path<String>,
) -> Result<Json<DidDocument>, ApiError> {
    let did = Did::parse(&did)?;
    let repo = vg_infra_pg::PgIdentityRepo;
    let mut tx = begin_tx(&state.pool).await?;
    let doc = repo.find_document(&mut tx, &did).await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    doc.map(Json).ok_or(ApiError::from(DomainError::NotFound))
}
