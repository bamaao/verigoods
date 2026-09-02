//! DID 注册、更新与查询。
//!
//! - `POST /api/v1/dids`：**引导操作**（新主体尚无签名者，Phase1 免签
//!   直写——中间件白名单放行）。防劫持三重约束（Task 24 定案）：
//!   1. **insert-only**：同 did 已存在 → 409（不 upsert——否则任意人
//!      可全量替换受害者文档劫持 active_pubkey）；
//!   2. **自派生绑定**：`did` 必须等于按 `method.id` 排序后首个方法
//!      `public_key` 摘要派生的 `did:vg:<hex>`（与 vg-infra-crypto
//!      `pubkey_to_did` 同口径），否则 400——防抢注他人 did；
//!   3. 合法密钥轮换走 `PUT /api/v1/dids`（需 VG-SIG 签名）。
//! - `PUT /api/v1/dids`：签名更新（**非白名单**）：校验签名者
//!   `AuthedDid == body.did`（他人不能替我更新）后 upsert
//!   `save_document`。**轮换风险**：全量替换后旧钥立即失效，客户端
//!   须确保 body 已含新钥，否则主体将无法再发起任何签名操作。
//! - `GET /api/v1/dids/{did}`：查询文档（VG-SIG 签名），404 未知 DID。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use vg_domain::identity::DidDocument;use vg_domain::shared::{Did, DomainError};

use crate::error::ApiError;
use crate::middleware::auth::AuthedDid;
use crate::routes::begin_tx;
use crate::state::SharedState;

/// 校验 DID 自派生绑定：`did == did:vg:<首个（按 id 排序）方法公钥摘要>`。
///
/// 与 vg-infra-crypto `pubkey_to_did` 口径一致（identity 模块的 DID 即由
/// keccak 公钥摘要派生）；不符返回 400，防止抢注他人 did。
fn ensure_self_derived(doc: &DidDocument) -> Result<(), ApiError> {
    let first = doc
        .methods
        .iter()
        .min_by(|a, b| a.id.cmp(&b.id))
        .ok_or_else(|| {
            ApiError::bad_request("DID 文档必须至少包含一个验证方法（methods 不能为空）")
        })?;
    let derived = format!("did:vg:{}", first.public_key.as_hex());
    if doc.did.as_str() != derived {
        return Err(ApiError::bad_request(
            "did 必须与首个验证方法公钥摘要一致（did:vg:<public_key>，按 method id 排序取首）",
        ));
    }
    Ok(())
}

/// 注册（insert-only）DID 文档：首次 201；已存在 409。
pub async fn register(
    State(state): State<SharedState>,
    crate::AppJson(doc): crate::AppJson<DidDocument>,
) -> Result<(StatusCode, Json<DidDocument>), ApiError> {
    ensure_self_derived(&doc)?;
    let repo = state.engine.deps().identity.clone();
    let mut tx = begin_tx(&state.pool).await?;
    if repo.find_document(&mut tx, &doc.did).await?.is_some() {
        return Err(ApiError::from(DomainError::AlreadyExists));
    }
    repo.save_document(&mut tx, &doc).await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    Ok((StatusCode::CREATED, Json(doc)))
}

/// 签名更新（upsert）DID 文档：合法密钥轮换路径。
///
/// - 签名者必须为文档主体本人（`AuthedDid == body.did`），否则 401；
/// - 通过后 `save_document` 全量替换（旧钥立即失效——轮换风险见模块 doc）。
pub async fn update(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(actor)): axum::Extension<AuthedDid>,
    crate::AppJson(doc): crate::AppJson<DidDocument>,
) -> Result<Json<DidDocument>, ApiError> {
    if actor != doc.did {
        return Err(ApiError::unauthorized("仅 DID 文档主体本人可更新该文档"));
    }
    let repo = state.engine.deps().identity.clone();
    let mut tx = begin_tx(&state.pool).await?;
    repo.save_document(&mut tx, &doc).await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    Ok(Json(doc))
}

/// 查询 DID 文档。
pub async fn get(
    State(state): State<SharedState>,
    Path(did): Path<String>,
) -> Result<Json<DidDocument>, ApiError> {
    let did = Did::parse(&did)?;
    let repo = state.engine.deps().identity.clone();
    let mut tx = begin_tx(&state.pool).await?;
    let doc = repo.find_document(&mut tx, &did).await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    doc.map(Json).ok_or(ApiError::from(DomainError::NotFound))
}
