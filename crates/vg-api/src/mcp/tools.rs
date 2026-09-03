//! MCP 工具全集（六组，设计 §6）：REST 路由层的薄等价物。
//!
//! 约定（与 [`crate::routes`] 完全一致）：
//! - **写操作**：actor 一律取自鉴权桥（[`super::actor_from_context`]，
//!   VG-SIG 签名者），工具入参**不含任何身份字段**；payload 组装 +
//!   `run_intent`（服务端 nonce / 10 分钟有效期 / 幂等 `intent_id` 可选）；
//! - **读操作**：读侧短事务即时返回；
//! - 返回值：成功 = JSON 文本 content；业务失败 = `CallToolResult::error`
//!   且 content 为 `{"code","message"}`（复用 [`crate::ApiError`] 口径）。
//!
//! 六组：commodity（5）/ ownership（2）/ transaction（5）/
//! credential（3）/ compliance（2）/ zk（2），共 19 个。

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_router};
use rmcp::{ErrorData, RoleServer};
use serde::Deserialize;
use serde_json::{json, Value};
use vg_domain::commodity::Batch;
use vg_domain::intent::IntentAction;
use vg_domain::ownership::{CustodyState, OwnershipState};
use vg_domain::shared::{Did, DomainError, SubjectRef};
use vg_domain::credential::VerifiableCredential;

use crate::error::ApiError;
use crate::mcp::{actor_from_context, McpServer};
use crate::routes::begin_tx;

// ---------- 通用助手 ----------

/// 成功：任意可序列化结果 → JSON 文本 content。
fn ok_json<T: serde::Serialize>(v: &T) -> Result<CallToolResult, ErrorData> {
    let text = serde_json::to_string(v)
        .map_err(|e| ErrorData::internal_error(format!("结果序列化失败：{e}"), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

/// 业务失败：`ApiError` → `{"code","message"}` 文本 content（is_error）。
fn err_json(e: ApiError) -> Result<CallToolResult, ErrorData> {
    let text = e.to_error_json().to_string();
    Ok(CallToolResult::error(vec![ContentBlock::text(text)]))
}

/// `subject_type`（`batch`/`asset`）+ id → [`SubjectRef`]；非法 → invalid_params。
fn subject_ref(kind: &str, id: &str) -> Result<SubjectRef, ErrorData> {
    match kind {
        "batch" => Ok(SubjectRef::Batch(vg_domain::shared::BatchId::new(id))),
        "asset" => Ok(SubjectRef::Asset(vg_domain::shared::AssetId::new(id))),
        other => Err(ErrorData::invalid_params(
            format!("subject_type 必须为 batch/asset，实际：{other}"),
            None,
        )),
    }
}

/// subject → payload JSON（`{"type","id"}` 对象）。
fn subject_value(s: &SubjectRef) -> Value {
    serde_json::to_value(s).expect("SubjectRef 序列化不可失败")
}

/// 可选 `on_behalf_of`（DID 字符串）解析。
fn on_behalf_of(raw: &Option<String>) -> Result<Option<Did>, ErrorData> {
    match raw {
        None => Ok(None),
        Some(s) => Did::parse(s).map(Some).map_err(|e| {
            ErrorData::invalid_params(format!("on_behalf_of 非法 DID：{e}"), None)
        }),
    }
}

/// 写操作公共段：组 payload → run_intent → 工具结果。
async fn run_tool(
    server: &McpServer,
    ctx: &RequestContext<RoleServer>,
    action: IntentAction,
    intent_id: Option<String>,
    ob: Option<Did>,
    payload: Value,
) -> Result<CallToolResult, ErrorData> {
    let actor = actor_from_context(ctx)?;
    let result = crate::routes::run_intent(
        &server.state.engine,
        actor,
        ob,
        action,
        intent_id,
        payload,
    )
    .await;
    match result {
        Ok(r) => ok_json(&r.0),
        Err(e) => err_json(e),
    }
}

// ---------- 参数结构 ----------

/// 写操作公共元字段（幂等键 + 被代理方）。
trait WriteMeta {
    fn intent_id(&self) -> Option<String>;
    fn on_behalf_of(&self) -> &Option<String>;
}

macro_rules! write_meta {
    ($t:ty) => {
        impl WriteMeta for $t {
            fn intent_id(&self) -> Option<String> {
                self.intent_id.clone()
            }
            fn on_behalf_of(&self) -> &Option<String> {
                &self.on_behalf_of
            }
        }
    };
}

/// 建批次入参。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateBatchParams {
    /// 批次 ID（subject 兼审计资源）。
    pub batch_id: String,
    /// 产品档案 ID（须已建档）。
    pub product_id: String,
    /// 数量（正整数）。
    pub quantity: u64,
    /// 单位（如 kg）。
    pub unit: String,
    /// 可选建档后生命周期迁移目标（snake_case，缺省停 Created）。
    pub target_state: Option<String>,
    /// 可选幂等重试键。
    pub intent_id: Option<String>,
    /// 可选被代理方 DID（Agent 代发）。
    pub on_behalf_of: Option<String>,
}
write_meta!(CreateBatchParams);

/// 拆分子批规格。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChildSpec {
    /// 子批 ID。
    pub id: String,
    /// 分配数量。
    pub quantity: u64,
}

/// 拆分批次入参。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SplitBatchParams {
    /// 父批 ID。
    pub batch_id: String,
    /// 子批分配表。
    pub children: Vec<ChildSpec>,
    /// 可选幂等重试键。
    pub intent_id: Option<String>,
    /// 可选被代理方 DID。
    pub on_behalf_of: Option<String>,
}
write_meta!(SplitBatchParams);

/// 合并批次入参。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MergeBatchParams {
    /// 参与合并的父批之一（须属于 children，消除路径歧义的同款契约）。
    pub batch_id: String,
    /// 参与合并的父批全集。
    pub children: Vec<String>,
    /// 合并产物新批 ID（subject 兼审计资源）。
    pub new_batch_id: String,
    /// 可选幂等重试键。
    pub intent_id: Option<String>,
    /// 可选被代理方 DID。
    pub on_behalf_of: Option<String>,
}
write_meta!(MergeBatchParams);

/// 建单品入参。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateItemParams {
    /// 单品 ID（subject 兼审计资源）。
    pub asset_id: String,
    /// 产品档案 ID。
    pub product_id: String,
    /// 真伪承诺（32 字节 hex，`0x` 前缀可选）。
    pub authenticity_commitment: String,
    /// 可选制造商说明。
    pub manufacturer: Option<String>,
    /// 可选幂等重试键。
    pub intent_id: Option<String>,
    /// 可选被代理方 DID。
    pub on_behalf_of: Option<String>,
}
write_meta!(CreateItemParams);

/// 主体定位入参（batch/asset + id）。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SubjectParams {
    /// `batch` 或 `asset`。
    pub subject_type: String,
    /// 对应主体 ID。
    pub subject_id: String,
}

/// 转移联动的保管变更规格。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CustodySpecParams {
    /// 新保管人 DID。
    pub to: String,
    /// 变更原因（`ship`/`warehouse_in`/`warehouse_out`/`handover`）。
    pub reason: String,
}

/// 公开转移入参。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TransferProductParams {
    /// `batch` 或 `asset`。
    pub subject_type: String,
    /// 对应主体 ID。
    pub subject_id: String,
    /// 受让方 DID。
    pub to: String,
    /// 是否跨企业转移。
    pub c2c: bool,
    /// 可选伴随生命周期迁移目标。
    pub lifecycle_to: Option<String>,
    /// 可选伴随保管变更。
    pub custody: Option<CustodySpecParams>,
    /// 可选幂等重试键。
    pub intent_id: Option<String>,
    /// 可选被代理方 DID。
    pub on_behalf_of: Option<String>,
}
write_meta!(TransferProductParams);

/// 保管更新入参。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateCustodyParams {
    /// `batch` 或 `asset`。
    pub subject_type: String,
    /// 对应主体 ID。
    pub subject_id: String,
    /// 新保管人 DID。
    pub to: String,
    /// 变更原因。
    pub reason: String,
    /// 可选伴随生命周期迁移目标。
    pub lifecycle_to: Option<String>,
    /// 可选幂等重试键。
    pub intent_id: Option<String>,
    /// 可选被代理方 DID。
    pub on_behalf_of: Option<String>,
}
write_meta!(UpdateCustodyParams);

/// 签发凭证入参。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IssueCredentialParams {
    /// `batch` 或 `asset`。
    pub subject_type: String,
    /// 对应主体 ID。
    pub subject_id: String,
    /// 受证人 DID。
    pub holder: String,
    /// 凭证类型（12 类 snake_case）。
    pub ctype: String,
    /// 主体声明集合（JSON 对象）。
    pub claims: Value,
    /// 可选过期时刻（RFC3339）。
    pub expires_at: Option<String>,
    /// 可选凭证 ID（缺省自动生成）。
    pub credential_id: Option<String>,
    /// 可选监管域 ID（提供时做 schema required_claims 校验）。
    pub domain_id: Option<String>,
    /// 可选幂等重试键。
    pub intent_id: Option<String>,
    /// 可选被代理方 DID。
    pub on_behalf_of: Option<String>,
}
write_meta!(IssueCredentialParams);

/// 撤销凭证入参。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RevokeCredentialParams {
    /// `batch` 或 `asset`。
    pub subject_type: String,
    /// 对应主体 ID。
    pub subject_id: String,
    /// 目标凭证 ID。
    pub credential_id: String,
    /// 可选撤销原因（审计留痕）。
    pub reason: Option<String>,
    /// 可选幂等重试键。
    pub intent_id: Option<String>,
    /// 可选被代理方 DID。
    pub on_behalf_of: Option<String>,
}
write_meta!(RevokeCredentialParams);

/// ID 入参（intent/proof/batch 等单字符串定位）。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IdParams {
    /// 目标 ID。
    pub id: String,
}

/// DID 主体入参（凭证列表）。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DidParams {
    /// 查询主体 DID。
    pub did: String,
}

/// Note 扫描入参。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ScanNotesParams {
    /// 接收方 view 私钥（64 hex）。
    pub view_priv: String,
    /// 接收方 spend 公钥（压缩点 hex）。
    pub spend_pub: String,
}

// ---------- 工具路由 ----------

#[tool_router(vis = "pub(crate)")]
impl McpServer {
    // ===== commodity =====

    /// 建批次：走意图管道（建档 + 初始所有权 + 可选生命周期迁移）。
    #[tool(description = "创建商品批次（意图管道写操作，返回 IntentResult）")]
    pub async fn mcp_create_batch(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(p): Parameters<CreateBatchParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let subject = subject_ref("batch", &p.batch_id)?;
        let payload = json!({
            "subject": subject_value(&subject),
            "product_id": p.product_id,
            "quantity": p.quantity,
            "unit": p.unit,
            "target_state": p.target_state,
        });
        run_tool(self, &ctx, IntentAction::CreateBatch, p.intent_id(), on_behalf_of(p.on_behalf_of())?, payload).await
    }

    /// 拆分批次：父批数量按 children 分配到子批。
    #[tool(description = "拆分批次为多个子批（意图管道，返回 IntentResult）")]
    pub async fn mcp_split_batch(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(p): Parameters<SplitBatchParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let subject = subject_ref("batch", &p.batch_id)?;
        let children: Vec<Value> = p
            .children
            .iter()
            .map(|c| json!({ "id": c.id, "quantity": c.quantity }))
            .collect();
        let payload = json!({
            "subject": subject_value(&subject),
            "children": children,
        });
        run_tool(self, &ctx, IntentAction::SplitBatch, p.intent_id(), on_behalf_of(p.on_behalf_of())?, payload).await
    }

    /// 合并批次：多父批合并为新批（new_batch_id 为业务产物）。
    #[tool(description = "合并多个批次为一个新批次（意图管道，返回 IntentResult）")]
    pub async fn mcp_merge_batch(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(p): Parameters<MergeBatchParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // 与 REST 同款契约：batch_id 必须属于 children（消除路径歧义）
        if !p.children.iter().any(|c| c == &p.batch_id) {
            return Err(ErrorData::invalid_params(
                "batch_id 必须是 children 中的父批之一",
                None,
            ));
        }
        let subject = subject_ref("batch", &p.new_batch_id)?;
        let payload = json!({
            "subject": subject_value(&subject),
            "children": p.children,
            "new_batch_id": p.new_batch_id,
        });
        run_tool(self, &ctx, IntentAction::MergeBatch, p.intent_id(), on_behalf_of(p.on_behalf_of())?, payload).await
    }

    /// 建单品：authenticity_commitment 为 32 字节 hex。
    #[tool(description = "创建单品档案（意图管道，返回 IntentResult）")]
    pub async fn mcp_create_item(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(p): Parameters<CreateItemParams>,
    ) -> Result<CallToolResult, ErrorData> {
        // 提前校验 hex 形状（与 REST 同款：好形状错误不过整管道才被拒）
        vg_domain::shared::Hash32::from_hex(&p.authenticity_commitment).map_err(|e| {
            ErrorData::invalid_params(format!("authenticity_commitment 非法：{e}"), None)
        })?;
        let subject = subject_ref("asset", &p.asset_id)?;
        let payload = json!({
            "subject": subject_value(&subject),
            "product_id": p.product_id,
            "authenticity_commitment": p.authenticity_commitment,
            "manufacturer": p.manufacturer,
        });
        run_tool(self, &ctx, IntentAction::CreateItem, p.intent_id(), on_behalf_of(p.on_behalf_of())?, payload).await
    }

    /// 批次聚合视图（同 REST `GET /api/v1/batches/{id}`）。
    #[tool(description = "批次聚合视图：批次档案+谱系+所有权+状态+计数")]
    pub async fn mcp_get_batch(
        &self,
        Parameters(p): Parameters<IdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let id = vg_domain::shared::BatchId::new(p.id);
        let mut tx = begin_tx(&self.state.pool).await.map_err(internal)?;
        let batch: Batch = match self.state.engine.deps().commodity.find_batch(&mut tx, &id).await {
            Ok(Some(b)) => b,
            Ok(None) => return err_json(ApiError::from(DomainError::NotFound)),
            Err(e) => return err_json(ApiError::from(e)),
        };
        let lineage = self
            .state
            .engine
            .deps()
            .commodity
            .lineage_of(&mut tx, &id)
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let ownership = self
            .state
            .engine
            .deps()
            .ownership
            .get(&mut tx, &SubjectRef::Batch(id.clone()))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let state_str = self
            .state
            .engine
            .deps()
            .lifecycle
            .current_state(&mut tx, &SubjectRef::Batch(id.clone()))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?
            .map(|s| s.as_str().to_owned())
            .unwrap_or_else(|| batch.state.as_str().to_owned());
        if let Err(e) = tx.commit().await {
            return err_json(ApiError::from(DomainError::Storage(format!("事务提交失败：{e}"))));
        }
        ok_json(&json!({
            "batch": batch,
            "lineage": lineage,
            "owner": ownership.as_ref().map(|o| o.owner.clone()),
            "transfer_count": ownership.as_ref().map(|o| o.transfer_count).unwrap_or(0),
            "c2c_count": ownership.as_ref().map(|o| o.c2c_count).unwrap_or(0),
            "state": state_str,
        }))
    }

    // ===== ownership =====

    /// 所有权档案查询。
    #[tool(description = "查询主体所有权档案（owner/计数；无档案返回 null）")]
    pub async fn mcp_get_ownership(
        &self,
        Parameters(p): Parameters<SubjectParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let subject = subject_ref(&p.subject_type, &p.subject_id)?;
        let mut tx = begin_tx(&self.state.pool).await.map_err(internal)?;
        let ownership: Option<OwnershipState> = self
            .state
            .engine
            .deps()
            .ownership
            .get(&mut tx, &subject)
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        if let Err(e) = tx.commit().await {
            return err_json(ApiError::from(DomainError::Storage(format!("事务提交失败：{e}"))));
        }
        ok_json(&ownership)
    }

    /// 保管档案查询。
    #[tool(description = "查询主体保管档案（custodian/since；无档案返回 null）")]
    pub async fn mcp_get_custody(
        &self,
        Parameters(p): Parameters<SubjectParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let subject = subject_ref(&p.subject_type, &p.subject_id)?;
        let mut tx = begin_tx(&self.state.pool).await.map_err(internal)?;
        let custody: Option<CustodyState> = self
            .state
            .engine
            .deps()
            .ownership
            .get_custody(&mut tx, &subject)
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        if let Err(e) = tx.commit().await {
            return err_json(ApiError::from(DomainError::Storage(format!("事务提交失败：{e}"))));
        }
        ok_json(&custody)
    }

    // ===== transaction =====

    /// 公开转移（所有权）。
    #[tool(description = "转移主体所有权（意图管道，返回 IntentResult）")]
    pub async fn mcp_transfer_product(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(p): Parameters<TransferProductParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let subject = subject_ref(&p.subject_type, &p.subject_id)?;
        let custody = p.custody.as_ref().map(|c| {
            json!({ "to": c.to, "reason": c.reason })
        });
        let payload = json!({
            "subject": subject_value(&subject),
            "to": p.to,
            "c2c": p.c2c,
            "lifecycle_to": p.lifecycle_to,
            "custody": custody,
        });
        run_tool(self, &ctx, IntentAction::TransferProduct, p.intent_id(), on_behalf_of(p.on_behalf_of())?, payload).await
    }

    /// 保管更新（不触碰所有权）。
    #[tool(description = "更新主体保管人（意图管道，返回 IntentResult）")]
    pub async fn mcp_update_custody(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(p): Parameters<UpdateCustodyParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let subject = subject_ref(&p.subject_type, &p.subject_id)?;
        let payload = json!({
            "subject": subject_value(&subject),
            "to": p.to,
            "reason": p.reason,
            "lifecycle_to": p.lifecycle_to,
        });
        run_tool(self, &ctx, IntentAction::UpdateCustody, p.intent_id(), on_behalf_of(p.on_behalf_of())?, payload).await
    }

    /// 意图详情（脱敏同 REST：shielded 花费密钥擦除）。
    #[tool(description = "查询意图详情（shielded payload 已脱敏）")]
    pub async fn mcp_get_intent(
        &self,
        Parameters(p): Parameters<IdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut tx = begin_tx(&self.state.pool).await.map_err(internal)?;
        let intent = self
            .state
            .engine
            .deps()
            .intents
            .get(&mut tx, &vg_domain::shared::IntentId::new(p.id.clone()))
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        if let Err(e) = tx.commit().await {
            return err_json(ApiError::from(DomainError::Storage(format!("事务提交失败：{e}"))));
        }
        match intent {
            Some(i) => ok_json(&crate::routes::intent::sanitize_intent(i)),
            None => err_json(ApiError::IntentNotFound(p.id)),
        }
    }

    /// 审批（L3/L4 停门续跑；approver = 鉴权桥签名者）。
    #[tool(description = "审批停在审批门的意图（approver 为 VG-SIG 签名者）")]
    pub async fn mcp_approve_intent(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(p): Parameters<IdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let approver = actor_from_context(&ctx)?;
        match self
            .state
            .engine
            .approve(&vg_domain::shared::IntentId::new(p.id), &approver)
            .await
        {
            Ok(r) => ok_json(&r),
            Err(e) => err_json(ApiError::from(e)),
        }
    }

    /// 转移历史（审计回放）。
    #[tool(description = "查询主体转移历史（TransferRecord 数组）")]
    pub async fn mcp_list_transfers(
        &self,
        Parameters(p): Parameters<SubjectParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let subject = subject_ref(&p.subject_type, &p.subject_id)?;
        let mut tx = begin_tx(&self.state.pool).await.map_err(internal)?;
        let records = self
            .state
            .engine
            .deps()
            .ownership
            .history(&mut tx, &subject)
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        if let Err(e) = tx.commit().await {
            return err_json(ApiError::from(DomainError::Storage(format!("事务提交失败：{e}"))));
        }
        ok_json(&records)
    }

    // ===== credential =====

    /// 签发凭证。
    #[tool(description = "签发可验证凭证（意图管道，返回 IntentResult）")]
    pub async fn mcp_issue_credential(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(p): Parameters<IssueCredentialParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let subject = subject_ref(&p.subject_type, &p.subject_id)?;
        let payload = json!({
            "subject": subject_value(&subject),
            "holder": p.holder,
            "ctype": p.ctype,
            "claims": p.claims,
            "expires_at": p.expires_at,
            "credential_id": p.credential_id,
            "domain_id": p.domain_id,
        });
        run_tool(self, &ctx, IntentAction::IssueCredential, p.intent_id(), on_behalf_of(p.on_behalf_of())?, payload).await
    }

    /// 撤销凭证（issuer-only）。
    #[tool(description = "撤销凭证（意图管道，返回 IntentResult）")]
    pub async fn mcp_revoke_credential(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(p): Parameters<RevokeCredentialParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let subject = subject_ref(&p.subject_type, &p.subject_id)?;
        let payload = json!({
            "subject": subject_value(&subject),
            "credential_id": p.credential_id,
            "reason": p.reason,
        });
        run_tool(self, &ctx, IntentAction::RevokeCredential, p.intent_id(), on_behalf_of(p.on_behalf_of())?, payload).await
    }

    /// 按主体列出凭证。
    #[tool(description = "按 DID 主体列出凭证（含 claims 与 credential_hash）")]
    pub async fn mcp_list_credentials(
        &self,
        Parameters(p): Parameters<DidParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let did = Did::parse(&p.did)
            .map_err(|e| ErrorData::invalid_params(format!("did 非法：{e}"), None))?;
        let mut tx = begin_tx(&self.state.pool).await.map_err(internal)?;
        let vcs: Vec<VerifiableCredential> = self
            .state
            .engine
            .deps()
            .credentials
            .list_by_subject(&mut tx, &did)
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        if let Err(e) = tx.commit().await {
            return err_json(ApiError::from(DomainError::Storage(format!("事务提交失败：{e}"))));
        }
        ok_json(&vcs)
    }

    // ===== compliance =====

    /// 合规检查（缺失凭证清单）。
    #[tool(description = "合规检查：返回 {compliant, missing[凭证类型]}")]
    pub async fn mcp_check_compliance(
        &self,
        Parameters(p): Parameters<SubjectParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let subject = subject_ref(&p.subject_type, &p.subject_id)?;
        let report = vg_application::services::compliance::check_compliance(
            self.state.engine.deps(),
            &subject,
        )
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        ok_json(&json!({
            "compliant": report.compliant,
            "missing": report.missing.iter().map(|t| t.as_str()).collect::<Vec<_>>(),
        }))
    }

    /// 必需凭证类型查询。
    #[tool(description = "查询主体必需的凭证类型列表")]
    pub async fn mcp_get_required_credentials(
        &self,
        Parameters(p): Parameters<SubjectParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let subject = subject_ref(&p.subject_type, &p.subject_id)?;
        let required = vg_application::services::compliance::get_required_credentials(
            self.state.engine.deps(),
            &subject,
        )
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        let list: Vec<&str> = required.iter().map(|t| t.as_str()).collect();
        ok_json(&list)
    }

    // ===== zk =====

    /// Shielded Note 扫描（view_priv/spend_pub 自扫）。
    #[tool(description = "扫描属于接收方（view 私钥+spend 公钥）的 Shielded Notes")]
    pub async fn mcp_scan_shielded_notes(
        &self,
        Parameters(p): Parameters<ScanNotesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let notes = vg_application::services::shielded::scan_notes(
            self.state.engine.deps(),
            &p.view_priv,
            &p.spend_pub,
        )
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        // 与 REST 同款：ScannedNote 无 Serialize，显式组装（不透出 spend 私钥）
        let items: Vec<Value> = notes
            .iter()
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
        ok_json(&items)
    }

    /// 证明记录查询（proof 字节以 hex 返回，体积可达数十 KB——调用方注意上下文预算）。
    #[tool(description = "按 proof_id 查询证明记录元数据+proof hex（体积较大）")]
    pub async fn mcp_get_proof(
        &self,
        Parameters(p): Parameters<IdParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let mut tx = begin_tx(&self.state.pool).await.map_err(internal)?;
        let record = self
            .state
            .engine
            .deps()
            .proofs
            .find(&mut tx, &p.id)
            .await
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        if let Err(e) = tx.commit().await {
            return err_json(ApiError::from(DomainError::Storage(format!("事务提交失败：{e}"))));
        }
        match record {
            Some(r) => ok_json(&json!({
                "proof_id": r.proof_id,
                "circuit_id": r.circuit_id,
                "circuit_version": r.circuit_version,
                "statement_hash": r.statement_hash.as_hex(),
                "proof": hex::encode(&r.proof),
                "publics": r.publics,
                "verified": r.verified,
            })),
            None => err_json(ApiError::from(DomainError::NotFound)),
        }
    }
}

/// DomainError → 协议层内部错误（begin_tx 等_transport 类失败）。
fn internal(e: DomainError) -> ErrorData {
    ErrorData::internal_error(e.to_string(), None)
}
