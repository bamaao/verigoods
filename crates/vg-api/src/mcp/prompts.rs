//! MCP 提示词全集（8 条中文文案模板，设计 §6）。
//!
//! 模板只做文案渲染（参数占位），不触达任何服务/仓储——参数由
//! LLM 客户端填充，渲染结果引导人类走对应工具或流程。

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{PromptMessage, Role};
use rmcp::ErrorData;
use rmcp::{prompt, prompt_router};
use serde::Deserialize;

use crate::mcp::McpServer;

// ---------- 参数结构 ----------

/// 单主体参数（批次/单品/产品定位 + 可选补充说明）。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SubjectPromptArgs {
    /// 主体（如 `batch:bt-001`）。
    pub subject: String,
}

/// 主体 + 原因（召回/争议等）。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SubjectReasonArgs {
    /// 主体（如 `batch:bt-001`）。
    pub subject: String,
    /// 事发原因或背景说明。
    pub reason: String,
}

/// 转移引导参数。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TransferGuideArgs {
    /// 主体（如 `batch:bt-001`）。
    pub subject: String,
    /// 受让方 DID。
    pub to: String,
}

/// 验真参数。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct VerifyArgs {
    /// 单品 ID（asset）。
    pub asset_id: String,
}

/// 监管披露参数。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DisclosureArgs {
    /// 主体（如 `batch:bt-001`）。
    pub subject: String,
    /// 监管辖区（如 `cn`）。
    pub jurisdiction: String,
}

/// 保管交接参数。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct HandoverArgs {
    /// 主体（如 `batch:bt-001`）。
    pub subject: String,
    /// 新保管人 DID。
    pub custodian: String,
}

/// 谱系争议参数。
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DisputeArgs {
    /// 争议主体（如 `batch:bt-001`）。
    pub subject: String,
    /// 争议主张方 DID。
    pub claimant: String,
    /// 争议焦点说明。
    pub dispute: String,
}

/// 单条 user 消息便捷构造。
fn user(text: String) -> Vec<PromptMessage> {
    vec![PromptMessage::new_text(Role::User, text)]
}

// ---------- 提示词路由（8 条） ----------

#[prompt_router(vis = "pub(crate)")]
impl McpServer {
    /// 批次溯源报告。
    #[prompt(
        name = "batch_trace_report",
        description = "生成批次全链路溯源报告框架"
    )]
    pub async fn prompt_batch_trace_report(
        &self,
        Parameters(a): Parameters<SubjectPromptArgs>,
    ) -> Result<Vec<PromptMessage>, ErrorData> {
        Ok(user(format!(
            "请为商品批次 {subject} 编制溯源报告，依次覆盖：\n\
             1. 批次档案与谱系（可调用 get_batch / 读取 commodity://batch/{{id}} 资源）；\n\
             2. 所有权与保管沿革（get_ownership / get_custody / list_transfers）；\n\
             3. 凭证与合规状态（list_credentials / check_compliance）；\n\
             4. 链上锚定与证明引用（get_proof）；\n\
             5. 结论：数据完整性判断与异常点提示。",
            subject = a.subject
        )))
    }

    /// 召回调查指引。
    #[prompt(
        name = "recall_investigation",
        description = "召回调查的取证与处置指引"
    )]
    pub async fn prompt_recall_investigation(
        &self,
        Parameters(a): Parameters<SubjectReasonArgs>,
    ) -> Result<Vec<PromptMessage>, ErrorData> {
        Ok(user(format!(
            "批次 {subject} 触发召回调查，事由：{reason}。请按以下步骤执行：\n\
             1. 锁定谱系上游（get_batch 的 lineage）与同源批次；\n\
             2. 检查相关凭证是否被撤销（list_credentials → CredStatus）；\n\
             3. 追踪全部下游受让方（list_transfers）并形成召回清单；\n\
             4. 评估合规缺口（check_compliance）；\n\
             5. 输出：召回范围、责任主体、处置建议（下架/隔离/销毁）。",
            subject = a.subject,
            reason = a.reason
        )))
    }

    /// 合规自查清单。
    #[prompt(name = "compliance_checklist", description = "主体合规自查清单")]
    pub async fn prompt_compliance_checklist(
        &self,
        Parameters(a): Parameters<SubjectPromptArgs>,
    ) -> Result<Vec<PromptMessage>, ErrorData> {
        Ok(user(format!(
            "请为主体 {subject} 生成合规自查清单：\n\
             1. 调用 get_required_credentials 列出必需凭证类型；\n\
             2. 调用 list_credentials 比对已持有凭证；\n\
             3. 调用 check_compliance 得到缺失清单；\n\
             4. 对每一项缺失给出补齐路径（issue_credential 所需 ctype/claims 建议）；\n\
             5. 提示过期临界凭证（expires_at 在 30 天内）。",
            subject = a.subject
        )))
    }

    /// 转移操作引导。
    #[prompt(name = "transfer_guide", description = "所有权转移操作分步引导")]
    pub async fn prompt_transfer_guide(
        &self,
        Parameters(a): Parameters<TransferGuideArgs>,
    ) -> Result<Vec<PromptMessage>, ErrorData> {
        Ok(user(format!(
            "请引导操作者完成 {subject} → {to} 的所有权转移：\n\
             1. 前置检查：get_ownership 确认当前权属、check_compliance 确认可流转；\n\
             2. 组装 transfer_product（subject/to/c2c，必要时附 custody 联动与 lifecycle_to）；\n\
             3. 高风险动作会停在审批门：用 get_intent 轮询，审批人调用 approve_intent；\n\
             4. 完成后回读 get_ownership / list_transfers 验证。\n\
             注意：actor 由 VG-SIG 签名绑定，操作者须为当前权利人或其授权 Agent。",
            subject = a.subject,
            to = a.to
        )))
    }

    /// 消费者验真指南。
    #[prompt(
        name = "consumer_verify",
        description = "消费者验真步骤指南（免签只读口径）"
    )]
    pub async fn prompt_consumer_verify(
        &self,
        Parameters(a): Parameters<VerifyArgs>,
    ) -> Result<Vec<PromptMessage>, ErrorData> {
        Ok(user(format!(
            "消费者验真单品 {asset_id} 的步骤：\n\
             1. 读取资源 commodity://asset/{{id}} 获取单品档案与真伪承诺；\n\
             2. 读取 commodity://product/{{id}} 核对产品元数据哈希；\n\
             3. 核验关联凭证状态（有效/撤销）与批次合规结论；\n\
             4. 如需链上核验：get_proof 取证明记录，对 statement_hash 与档案比对。\n\
             提醒：消费者侧全部为脱敏只读视图，不暴露完整 DID 与转移明细。",
            asset_id = a.asset_id
        )))
    }

    /// 监管披露申请。
    #[prompt(
        name = "regulatory_disclosure",
        description = "向监管方发起数据披露申请的文案模板"
    )]
    pub async fn prompt_regulatory_disclosure(
        &self,
        Parameters(a): Parameters<DisclosureArgs>,
    ) -> Result<Vec<PromptMessage>, ErrorData> {
        Ok(user(format!(
            "请起草针对 {subject} 的监管披露申请（辖区 {jurisdiction}）：\n\
             1. 披露范围：批次档案、谱系、转移历史、凭证与合规报告；\n\
             2. 法律依据与最小必要原则说明；\n\
             3. 数据口径：监管解密（shielded/decrypt）需未过期的数据访问授权\n\
                （validium/grants），请在申请中说明授权依据；\n\
             4. 输出格式：申请函正文 + 附件清单（各资源 URI）。",
            subject = a.subject,
            jurisdiction = a.jurisdiction
        )))
    }

    /// 保管交接确认。
    #[prompt(name = "custody_handover", description = "保管交接的核对与确认清单")]
    pub async fn prompt_custody_handover(
        &self,
        Parameters(a): Parameters<HandoverArgs>,
    ) -> Result<Vec<PromptMessage>, ErrorData> {
        Ok(user(format!(
            "请为 {subject} → 保管人 {custodian} 的交接编制确认清单：\n\
             1. 交接前：get_custody 记录现保管人，get_ownership 确认权属未变；\n\
             2. 执行 update_custody（reason=handover，必要时附 lifecycle_to）；\n\
             3. 交接后：回读 get_custody 核对新保管人与 since 时点；\n\
             4. 留痕：记录 intent_id 与本次清单签署人（VG-SIG 签名者）。",
            subject = a.subject,
            custodian = a.custodian
        )))
    }

    /// 谱系争议取证。
    #[prompt(name = "lineage_dispute", description = "谱系争议的取证与裁决材料框架")]
    pub async fn prompt_lineage_dispute(
        &self,
        Parameters(a): Parameters<DisputeArgs>,
    ) -> Result<Vec<PromptMessage>, ErrorData> {
        Ok(user(format!(
            "主体 {subject} 发谱系争议：主张方 {claimant}，争议焦点：{dispute}。\n\
             请按取证框架输出：\n\
             1. 谱系事实：get_batch 的 lineage 边集与数量守恒核对（split/merge 记账）；\n\
             2. 时间线：list_transfers 的转移序列 + 各意图的创建/审批时点（get_intent）；\n\
             3. 密码学证据：涉及单品的 authenticity_commitment 与 get_proof 证明记录；\n\
             4. 裁决建议：依据链上锚定与审计记录给出争议事实认定与责任划分。",
            subject = a.subject,
            claimant = a.claimant,
            dispute = a.dispute
        )))
    }
}
