//! # MCP 服务层（Task 25）：rmcp `ServerHandler` + streamable-http 挂载。
//!
//! 设计（设计文档 §6）：Agent 经 MCP（Tools / Resources / Prompts）访问
//! 与 REST 完全同一套应用服务——写操作组装 [`RawIntent`] 走
//! `IntentEngine` 管道，读操作走读侧短事务，**无直连链权限**。
//!
//! ## 鉴权桥（方案定案：按请求 HTTP extension 透传）
//!
//! `/mcp` 由 [`mcp_service`] 构造的 rmcp `StreamableHttpService` 承载，
//! 挂在生产 Router 的 VG-SIG 中间件**之内**（中间件在 Router 最外层）。
//! rmcp 3.2 的 streamable-http transport 会把每个 HTTP 请求的
//! `http::request::Parts`（含中间件注入的 [`AuthedDid`] extension 与
//! 全部头）塞进对应 JSON-RPC 请求的 `RequestContext.extensions`
//! （见 rmcp `tower.rs` doc "Accessing custom axum/tower extension state"）。
//! 因此工具体经 [`actor_from_context`] 读出的 actor **严格等于该次
//! HTTP 请求 VG-SIG 签名验证通过的 DID**：
//! - 不裸信任工具入参的任何 actor 字段（工具 schema 中根本不存在）；
//! - 无需会话注册表：streamable-http 每 POST 请求都带 VG-SIG 头
//!   （"连接级"签名在每请求校验语义下等效），且 GET SSE / DELETE
//!   同样被中间件覆盖；
//! - 已知限制：会话的 `initialize` 与后续工具调用可以来自不同签名者
//!   （MCP 会话与 VG-SIG 身份不绑定），但每次工具调用的 actor 都以
//!   **当次请求**的签名为准，冒充在单次请求粒度上即被阻断。
//!
//! ### `mcp-mock-auth` feature（默认关闭，仅测试）
//!
//! 开启后 [`actor_from_context`] 不再要求 `AuthedDid` extension，直接
//! 返回固定测试 DID（`did:vg:` + `22`*32 hex）。**生产构建严禁开启**：
//! 仅供无 HTTP 层的 in-process rmcp 客户端集成测试走通管道。
//!
//! ## 模块
//!
//! - [`tools`]：六组工具（commodity / ownership / transaction /
//!   credential / compliance / zk）——`#[tool_router]` 全集；
//! - [`resources`]：`commodity://` 三类 URI 模板的读取（读侧短事务）；
//! - [`prompts`]：8 条中文文案模板——`#[prompt_router]` 全集。
//!
//! ## 错误口径
//!
//! 业务失败（领域错误 / 意图拒绝）是"工具跑了但没成功"：返回
//! `CallToolResult::error`，内容为 `{"code": <snake 码>, "message": ...}`
//! （复用 [`crate::ApiError`] 的安全文案与 snake 码，Storage 脱敏同
//! REST）。协议层错误（JSON-RPC `Err`）只用于不可路由场景。

pub mod prompts;
pub mod resources;
pub mod tools;

use std::sync::Arc;

use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use vg_domain::shared::{Did, DomainError};

use crate::state::SharedState;
#[cfg(not(feature = "mcp-mock-auth"))]
use crate::middleware::auth::AuthedDid;

/// MCP 服务端句柄：持有与 REST 路由同一份共享状态。
#[derive(Clone)]
pub struct McpServer {
    /// 共享应用状态（engine + pool；鉴权桥供 actor）。
    pub(crate) state: SharedState,
    /// 工具路由（`#[tool_router]` 生成，见 [`tools`]）。
    pub(crate) tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
    /// 提示词路由（`#[prompt_router]` 生成，见 [`prompts`]）。
    pub(crate) prompt_router: rmcp::handler::server::router::prompt::PromptRouter<Self>,
}

impl McpServer {
    /// 构造（factory 每请求调用，状态为 `Arc` 克隆，开销可忽略）。
    pub fn new(state: SharedState) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
            prompt_router: Self::prompt_router(),
        }
    }
}

/// 鉴权桥：从工具调用上下文取 VG-SIG 验签通过的 actor DID。
///
/// 生产实现见模块 doc（`http::request::Parts` → `AuthedDid`）；
/// `mcp-mock-auth` 下直通固定测试 DID。
pub(crate) fn actor_from_context(
    #[cfg_attr(feature = "mcp-mock-auth", allow(unused_variables))] ctx: &rmcp::service::RequestContext<RoleServer>,
) -> Result<Did, ErrorData> {
    #[cfg(feature = "mcp-mock-auth")]
    {
        // ⚠ 仅测试：无 HTTP 层的 in-process 客户端直通固定 DID。
        let did = Did::parse(&format!("did:vg:{}", "22".repeat(32)))
            .expect("固定测试 DID 语法合法");
        Ok(did)
    }
    #[cfg(not(feature = "mcp-mock-auth"))]
    {
        let parts = ctx
            .extensions
            .get::<http::request::Parts>()
            .ok_or_else(|| {
                ErrorData::internal_error(
                    "MCP 请求缺少 HTTP 上下文（actor 绑定 VG-SIG 签名，仅接受经 /mcp 挂载的请求）",
                    None,
                )
            })?;
        parts
            .extensions
            .get::<AuthedDid>()
            .map(|AuthedDid(did)| did.clone())
            .ok_or_else(|| {
                ErrorData::internal_error(
                    "MCP 请求未携带 VG-SIG 鉴权身份（AuthedDid 缺失）",
                    None,
                )
            })
    }
}

/// DomainError → 协议层内部错误（tools / resources 共用）。
///
/// Storage 变体脱敏：sqlx 细节（含错误原文）不进 JSON-RPC 响应，
/// 只落 tracing 日志；其余变体（多为读侧意外）保留 `to_string` 文案。
pub(crate) fn internal_err(e: DomainError) -> ErrorData {
    if matches!(e, DomainError::Storage(_)) {
        tracing::error!(code = "storage", original = %e, "MCP 协议层存储错误（已脱敏）");
        return ErrorData::internal_error("内部存储错误", None);
    }
    ErrorData::internal_error(e.to_string(), None)
}

/// 读事务提交（失败折叠为脱敏 Storage 错误 → 协议层内部错误）。
///
/// MCP 读侧共用宏（resources / tools 均可用；tools 的业务读工具
/// 自行经 `err_json` 走业务错误口径，不受此宏约束）。
macro_rules! commit {
    ($tx:expr) => {
        if let Err(e) = $tx.commit().await {
            return Err(internal_err(DomainError::Storage(format!("事务提交失败：{e}"))));
        }
    };
}
pub(crate) use commit;

/// 构造 `/mcp` 挂载的 streamable-http service（POST/GET/DELETE 由
/// rmcp 按协议处理；每请求均经 VG-SIG 中间件）。
pub fn mcp_service(state: SharedState) -> StreamableHttpService<McpServer, LocalSessionManager> {
    StreamableHttpService::new(
        move || Ok(McpServer::new(state.clone())),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    )
}

/// ServerHandler 实现：工具/提示词路由宏 + 手写资源方法（见 [`resources`]）。
#[rmcp::tool_handler(router = self.tool_router)]
#[rmcp::prompt_handler(router = self.prompt_router)]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        // 能力声明：tools + prompts + resources（resources 由手写方法提供）
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .build(),
        )
        .with_instructions(
            "VeriGoods 可验证商品生命周期服务：写操作走意图管道（异步审批），\
             读操作即时返回；actor 由 VG-SIG 请求签名绑定，工具入参不含身份字段。",
        )
    }

    // ---- 资源方法（手写，见 [`resources`]；宏只生成缺失方法，不冲突） ----

    /// resources/list：模板型资源不枚举实例。
    async fn list_resources(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, rmcp::ErrorData> {
        self.mcp_list_resources(request, context).await
    }

    /// resources/templates/list：三类 `commodity://` 模板。
    async fn list_resource_templates(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListResourceTemplatesResult, rmcp::ErrorData> {
        self.mcp_list_resource_templates(request, context).await
    }

    /// resources/read：URI 模板解析 → 读侧短事务查询。
    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResponse, rmcp::ErrorData> {
        self.mcp_read_resource(request, context).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Storage 变体脱敏：输出不含原文、含"内部存储错误"；
    /// 其余变体保留 Display 原文。
    #[test]
    fn internal_err_sanitizes_storage_only() {
        let e = internal_err(DomainError::Storage(
            "sqlx: connection refused (postgres://secret@db)".into(),
        ));
        let msg = e.message.to_string();
        assert!(msg.contains("内部存储错误"));
        assert!(!msg.contains("sqlx"));
        assert!(!msg.contains("secret"));

        let e = internal_err(DomainError::InvalidTransition {
            from: "Active".into(),
            to: "Retired".into(),
        });
        let msg = e.message.to_string();
        assert!(msg.contains("Active"));
        assert!(msg.contains("Retired"));
    }
}
