//! MCP 资源（设计 §6）：`commodity://` 三类 URI 模板。
//!
//! - `commodity://batch/{id}`：批次聚合（批次档案 + 谱系 + 所有权 + 状态 +
//!   计数，同 REST `GET /api/v1/batches/{id}`）；
//! - `commodity://asset/{id}`：单品档案；
//! - `commodity://product/{id}`：产品档案。
//!
//! 读取走读侧短事务；`list_resources` 不枚举具体实例（实例开放集合，
//! 一律经 `resources/templates/list` 发现）。rmcp 3.2 无 resource 宏，
//! 三个 `ServerHandler` 方法（list_resources / list_resource_templates /
//! read_resource）在 [`super::McpServer`] 的 `impl ServerHandler`（mod.rs）
//! 中显式实现并委托本模块。

use rmcp::model::{
    ListResourceTemplatesResult, ListResourcesResult, ReadResourceRequestParams,
    ReadResourceResponse, ReadResourceResult, Resource, ResourceContents, ResourceTemplate,
};
use rmcp::model::PaginatedRequestParams;
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer};
use vg_domain::commodity::{Asset, ProductType};
use vg_domain::shared::{AssetId, BatchId, DomainError, ProductId};

use crate::mcp::{commit, internal_err, McpServer};
use crate::routes::begin_tx;

impl McpServer {
    /// 三类资源模板（静态）。
    pub(crate) fn resource_templates() -> Vec<ResourceTemplate> {
        vec![
            ResourceTemplate::new("commodity://batch/{id}", "batch")
                .with_title("批次聚合视图")
                .with_description("批次档案 + 谱系 + 所有权 + 生命周期状态 + 转移计数")
                .with_mime_type("application/json"),
            ResourceTemplate::new("commodity://asset/{id}", "asset")
                .with_title("单品档案")
                .with_description("单品档案（真伪承诺 / 产品关联 / 制造商）")
                .with_mime_type("application/json"),
            ResourceTemplate::new("commodity://product/{id}", "product")
                .with_title("产品档案")
                .with_description("产品建档档案（类目 / 元数据哈希）")
                .with_mime_type("application/json"),
        ]
    }

    /// 解析 `commodity://{kind}/{id}` → (kind, id)。
    pub(crate) fn parse_uri(uri: &str) -> Result<(String, String), ErrorData> {
        let rest = uri.strip_prefix("commodity://").ok_or_else(|| {
            ErrorData::invalid_params(
                format!("不支持的资源 URI（须为 commodity:// 前缀）：{uri}"),
                None,
            )
        })?;
        let (kind, id) = rest.split_once('/').ok_or_else(|| {
            ErrorData::invalid_params(
                format!("资源 URI 须为 commodity://{{kind}}/{{id}}：{uri}"),
                None,
            )
        })?;
        if id.is_empty() || id.contains('/') {
            return Err(ErrorData::invalid_params(
                format!("资源 URI 的 id 段非法（不得为空或含 /）：{uri}"),
                None,
            ));
        }
        Ok((kind.to_owned(), id.to_owned()))
    }

    /// resources/list：模板型资源不枚举实例（空清单）。
    pub(crate) async fn mcp_list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult {
            resources: Vec::<Resource>::new(),
            ..Default::default()
        })
    }

    /// resources/templates/list：三类 `commodity://` 模板。
    pub(crate) async fn mcp_list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        Ok(ListResourceTemplatesResult {
            resource_templates: Self::resource_templates(),
            ..Default::default()
        })
    }

    /// resources/read：URI 模板解析 → 读侧短事务查询。
    pub(crate) async fn mcp_read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let (kind, id) = Self::parse_uri(&request.uri)?;
        let contents = self.read_commodity(&kind, &id).await?;
        Ok(ReadResourceResult::new(vec![contents]).into())
    }

    /// 读取一个资源 → JSON 文本内容（短事务）。
    async fn read_commodity(&self, kind: &str, id: &str) -> Result<ResourceContents, ErrorData> {
        let uri = format!("commodity://{kind}/{id}");
        let value = match kind {
            "batch" => {
                let bid = BatchId::new(id);
                let mut tx = begin_tx(&self.state.pool).await.map_err(internal_err)?;
                // 聚合组装走 REST 同款唯一口径（一处化）
                let value = match crate::routes::commodity::batch_aggregate(
                    self.state.engine.deps(),
                    &mut tx,
                    &bid,
                )
                .await
                {
                    Ok(v) => v,
                    Err(DomainError::NotFound) => return Err(not_found(&uri)),
                    Err(e) => return Err(internal_err(e)),
                };
                commit!(tx);
                value
            }
            "asset" => {
                let aid = AssetId::new(id);
                let mut tx = begin_tx(&self.state.pool).await.map_err(internal_err)?;
                let asset: Option<Asset> = self
                    .state
                    .engine
                    .deps()
                    .commodity
                    .find_asset(&mut tx, &aid)
                    .await
                    .map_err(internal_err)?;
                commit!(tx);
                match asset {
                    Some(a) => serde_json::to_value(&a).map_err(serialize)?,
                    None => return Err(not_found(&uri)),
                }
            }
            "product" => {
                let pid = ProductId::new(id);
                let mut tx = begin_tx(&self.state.pool).await.map_err(internal_err)?;
                let product: Option<ProductType> = self
                    .state
                    .engine
                    .deps()
                    .commodity
                    .find_product(&mut tx, &pid)
                    .await
                    .map_err(internal_err)?;
                commit!(tx);
                match product {
                    Some(p) => serde_json::to_value(&p).map_err(serialize)?,
                    None => return Err(not_found(&uri)),
                }
            }
            other => {
                return Err(ErrorData::invalid_params(
                    format!("不支持的资源类型（batch/asset/product）：{other}"),
                    None,
                ))
            }
        };
        let text = serde_json::to_string_pretty(&value).map_err(serialize)?;
        Ok(ResourceContents::text(text, uri).with_mime_type("application/json"))
    }
}

/// 资源不存在：按新版协议口径映射 invalid_params（旧口径由 SDK 统一改写）。
fn not_found(uri: &str) -> ErrorData {
    ErrorData::invalid_params(format!("目标资源不存在：{uri}"), None)
}

fn serialize(e: serde_json::Error) -> ErrorData {
    ErrorData::internal_error(format!("资源序列化失败：{e}"), None)
}
