//! IntentEngine：Intent 管道编排（全系统**唯一写入口径**的执行核）。
//!
//! 管道（与 [`IntentStatus`] 各阶段一一对应，设计文档 §27）：
//!
//! ```text
//! execute(raw)：
//!   事务开启 → Intent::new 校验（失败不落库）
//!   → insert（同 id 冲突 = 幂等返回既有结果；(actor,nonce) 冲突 = ReplayDetected）
//!   → 过期双保险 → Validated → 授权（DID/Agent/能力）
//!   → SAVEPOINT handler_sp → handler.handle
//!        ├─ Err → ROLLBACK TO SAVEPOINT（业务段回滚）
//!        │        → intent.reject(reason) → save → audit(deny) → commit
//!        ├─ AwaitingApproval{role} → approvals 落未决行 → save（停在 Approved 前）→ commit
//!        └─ Completed{result_ref} → Approved → Submitted → Confirmed(result_ref)
//!                                 → save → audit(allow) → commit
//!
//! approve(intent_id, approver)：   // L3/L4 审批门续跑后半程
//!   事务开启 → get（NotFound/终态拒绝）→ 过期检查 → approvals.find
//!   → 已决策 = 幂等返回当前状态
//!   → 审批人 SubjectKind 匹配 required_role → mark_decided（一次性）
//!   → SAVEPOINT handler_sp → handler.handle（handler 查 approvals 已决策 → 过门）
//!   → 与 execute 同一收尾函数
//! ```
//!
//! **savepoint 语义**：handler 业务段（聚合写入/outbox/锚定前奏）失败时
//! `ROLLBACK TO SAVEPOINT handler_sp` 只回滚业务写入，intent 本体
//! （insert/推进/reject/审计）在 savepoint 之外落库并 commit——审计要求的
//! 「拒绝也要留痕」由此达成（Intent 永不因 handler 失败而消失；存储层
//! 自身故障除外——commit 失败即全部丢失）。
//!
//! **已知缺口（悬挂锚）**：savepoint 只能回滚**本事务内**的写入；若 handler
//! 在业务校验/聚合落库**之前**调用独立提交的账本锚定（`ledger.anchor`
//! 自开事务），Err 路径的 `ROLLBACK TO SAVEPOINT` 撤不掉已提交的锚定，
//! 形成悬挂锚。且 transfer/lifecycle_change 等 5 种 kind 的账本分录无唯一
//! 索引，重试会二次记账污染链。**契约**：`ledger.anchor` 必须是 handler 内
//! 最后一个不可逆步骤（见 [`IntentHandler::handle`]）。Phase2 演进方向：
//! outbox 驱动锚定 + 对账补偿（锚定与业务写入同事务发 outbox，由投递器
//! 保证最终一致），届时本缺口闭环。
//!
//! **Action 映射**（intent 动作 → identity 能力，见 [`required_capability`]）：
//! 两套枚举各自演化，映射是本模块唯一的桥接点。

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vg_domain::identity::capability::Action as CapabilityAction;
use vg_domain::intent::{Intent, IntentAction, IntentStatus, RiskLevel};
use vg_domain::policy::PolicyVersion;
use vg_domain::shared::{Did, DomainError, IntentId, ProofId};
use vg_infra_pg::audit::AuditEntry;

use crate::deps::{AppDeps, PgTx};
use crate::error::AppError;

/// 业务段的 SAVEPOINT 名（业务回滚锚点）。
const HANDLER_SAVEPOINT: &str = "handler_sp";

/// 引擎入口的原始意图（未落库、未校验的调用方载荷）。
#[derive(Debug, Clone)]
pub struct RawIntent {
    /// 唯一标识（幂等键）。
    pub id: IntentId,
    /// 业务动作。
    pub action: IntentAction,
    /// 发起人 DID。
    pub actor: Did,
    /// 代理发起时的被代理企业 DID（Agent 代发场景）。
    pub on_behalf_of: Option<Did>,
    /// 动作参数（JSON object）。
    pub payload: Value,
    /// 防重放单调值。
    pub nonce: u64,
    /// 过期时间。
    pub expires_at: DateTime<Utc>,
    //
    // 隐含 schema 约定：拒绝路径的审计资源取 `payload["subject"]`（见
    // `deny_resource`，缺省以动作名兜底）——Task 20 起各 handler 的载荷
    // **必须**含 `subject` 字段（`SubjectRef` 对象形
    // `{"type":"batch","id":"bt-1"}`），否则拒绝审计的 resource 退化为
    // 动作名，可观测性受损。
}

/// 引擎执行结果（幂等重复提交返回同一结果）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentResult {
    /// 意图 ID。
    pub intent_id: String,
    /// 管道当前状态。
    pub status: IntentStatus,
    /// 风险分级（由 action 推导）。
    pub risk: RiskLevel,
    /// 执行结果引用（仅 Confirmed 有值，如链上交易哈希）。
    pub result_ref: Option<String>,
    /// 拒绝原因（仅 Rejected 有值）。
    pub rejection: Option<String>,
    /// 是否停在审批门。
    ///
    /// 统一口径：`approvals 行存在 && intent 状态未达 Approved 且非终态`
    /// （见 [`awaiting_status`]）。三种典型情形：
    /// - execute 首次停门（status=Proved，行未决）→ true；
    /// - 幂等重放已 Confirmed（终态）→ false；
    /// - 并发中途值（status=Proved，行已决策但续跑事务未提交）→ true
    ///   （仍标等待中，客户端以 `status` 为准判断实际进度）。
    pub awaiting_approval: bool,
}

/// 单个动作的管道业务段处理器（Task 20/21/22 逐动作注册）。
///
/// 职责边界（engine 之外的全部管道段）：业务校验 → policy engine →
/// prover（需要时）→ ledger.anchor → 聚合变更落库 → outbox 事件；
/// 并沿路推进 intent 状态（PolicyChecked / ProofRequired / Proved）。
///
/// **⚠ 悬挂锚契约**：`ledger.anchor` 必须是 handler 内**最后一个不可逆
/// 步骤**——所有可能返回 Err 的业务校验与聚合落库全部完成之后才锚定。
/// 原因：`ledger.anchor` 独立开事务提交，engine 的 `ROLLBACK TO
/// SAVEPOINT handler_sp` 撤不掉它；若锚定后仍有可失败步骤，Err 回滚会
/// 留下悬挂锚，且 transfer/lifecycle_change 等 5 种 kind 无唯一索引，
/// 重试会二次记账污染链。Phase2 将以 outbox 驱动锚定 + 对账补偿闭环。
///
/// **SAVEPOINT 嵌套**：handler 可自开更细粒度的 SAVEPOINT 做局部回滚，
/// 命名必须避开保留名 `handler_sp`（engine 的业务段回滚锚点）。
///
/// **载荷 schema 约定**：拒绝路径审计资源取 `payload["subject"]`
/// （见 [`RawIntent`] 的隐含 schema 说明）。
///
/// **续跑幂等**：L3/L4 审批门场景下 handle 会被调用两次（门内一次、
/// approve 后一次）。第二次进入时 intent 状态停在门前的位置（如 Proved），
/// handler 必须按当前状态分岔推进（已过的段不重推、幂等的写入可重放）。
#[async_trait]
pub trait IntentHandler: Send + Sync {
    /// 该处理器承担的动作（注册键）。
    fn action(&self) -> IntentAction;
    /// 执行业务段。
    ///
    /// `tx` 与 engine 共享同一事务：业务写入落在 [`HANDLER_SAVEPOINT`]
    /// 保护范围内，Err 即被 engine 回滚。L3/L4 审批门通过「查
    /// approvals 行是否已决策」自行分岔：未决策返回
    /// [`HandlerOutcome::AwaitingApproval`]，已决策继续后半程直至
    /// [`HandlerOutcome::Completed`]。
    async fn handle(
        &self,
        deps: &AppDeps,
        tx: &mut PgTx,
        intent: &mut Intent,
        now: DateTime<Utc>,
    ) -> Result<HandlerOutcome, DomainError>;
}

/// 业务段结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerOutcome {
    /// 业务段完成（已锚定/落库/outbox），`result_ref` 供 confirm。
    Completed {
        /// 执行结果引用（如链上交易哈希）。
        result_ref: String,
        /// 审计资源标识（如 `batch:bt-1`）。
        resource: String,
        /// 本次执行实际生效的策略版本集合（Task 20 起 handler 携带，
        /// engine 审计列 `policy_id` / `policy_version` 取**最后一条**
        /// enforced 版本——多条适用策略全部执行的审计口径，doc 锁定）。
        policy: Vec<PolicyVersion>,
        /// 关联的 ZK 证明 ID（无证明路径为 `None`，Task 21/22 填充）。
        proof_id: Option<ProofId>,
    },
    /// L3/L4 审批门：已通过业务校验/policy/证明，等待审批。
    AwaitingApproval {
        /// 要求的审批人 SubjectKind（snake_case，如 `regulator`）。
        required_role: String,
    },
}

/// 动作 → 处理器的注册表。
#[derive(Clone, Default)]
pub struct HandlerMap {
    handlers: HashMap<IntentAction, Arc<dyn IntentHandler>>,
}

impl HandlerMap {
    /// 空注册表。
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册处理器（同动作后写覆盖先写）。
    pub fn register(&mut self, handler: Arc<dyn IntentHandler>) {
        self.handlers.insert(handler.action(), handler);
    }

    /// 查找处理器；未注册返回 [`DomainError::InvalidInput`]。
    pub fn get(&self, action: &IntentAction) -> Result<Arc<dyn IntentHandler>, DomainError> {
        self.handlers.get(action).cloned().ok_or_else(|| {
            DomainError::InvalidInput(format!("动作未注册处理器：{}", action.as_str()))
        })
    }

    /// 已注册的动作数（诊断/测试用）。
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// 是否为空注册表。
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

/// intent 动作 → identity 能力的映射表（Phase1 口径）。
///
/// | IntentAction | CapabilityAction | 说明 |
/// |---|---|---|
/// | `CreateBatch` | `CreateBatch` | 建档 |
/// | `SplitBatch` / `MergeBatch` / `TransformBatch` / `CreateItem` | `CreateBatch` | 谱系/单品建档类，以创建批次能力承载 |
/// | `TransferProduct` | `TransferOwnership` | 所有权转移 |
/// | `UpdateCustody` | `UpdateCustody` | 保管更新 |
/// | `IssueCredential` | `IssueCredential` | 签证 |
/// | `RevokeCredential` | `RevokeCredential` | 撤证 |
/// | `ShieldedTransfer` | `SubmitShieldedTx` | 隐形转移 |
/// | `MassRecall` | `MassRecall` | 召回 |
/// | `ComplianceCheck` | — | L1 读/验类，免能力 |
/// | `SubmitStateRoot` | — | 系统级结算，免能力 |
///
/// 返回 `None` 即跳过能力校验（授权段仅做 DID 存在性检查）。
pub fn required_capability(action: IntentAction) -> Option<CapabilityAction> {
    match action {
        IntentAction::ComplianceCheck | IntentAction::SubmitStateRoot => None,
        IntentAction::CreateBatch
        | IntentAction::SplitBatch
        | IntentAction::MergeBatch
        | IntentAction::TransformBatch
        | IntentAction::CreateItem => Some(CapabilityAction::CreateBatch),
        IntentAction::TransferProduct => Some(CapabilityAction::TransferOwnership),
        IntentAction::UpdateCustody => Some(CapabilityAction::UpdateCustody),
        IntentAction::IssueCredential => Some(CapabilityAction::IssueCredential),
        IntentAction::RevokeCredential => Some(CapabilityAction::RevokeCredential),
        IntentAction::ShieldedTransfer => Some(CapabilityAction::SubmitShieldedTx),
        IntentAction::MassRecall => Some(CapabilityAction::MassRecall),
    }
}

/// Intent 引擎：管道编排核。
pub struct IntentEngine {
    deps: AppDeps,
    handlers: HandlerMap,
}

impl IntentEngine {
    /// 构造引擎（deps 经 bootstrap 装配，handlers 由 Task 20/21/22 注册）。
    pub fn new(deps: AppDeps, handlers: HandlerMap) -> Self {
        Self { deps, handlers }
    }

    /// 执行一条原始意图：全管道编排（见模块级管道图）。
    ///
    /// **幂等口径**：按 `id` 返回当前快照，**不比对载荷**（同 id 不同
    /// payload 的重放得到的是首次意图的结果）；并发下可能返回管道
    /// 中途态（如 Authorized/Proved）快照。
    pub async fn execute(&self, raw: RawIntent) -> Result<IntentResult, AppError> {
        let mut tx = self.deps.pool.begin().await.map_err(storage_err)?;
        let now = Utc::now();

        // b. 构造校验失败（payload 非 object / expires 已过）连 intent 都不该有：
        //    直接放弃事务返回，不落任何行。
        let mut intent = Intent::new(
            raw.id,
            raw.action,
            raw.actor,
            raw.on_behalf_of,
            raw.payload,
            raw.nonce,
            now,
            raw.expires_at,
        )?;

        // c. insert 幂等两层：同 id → 既有结果；(actor,nonce) 冲突 → 重放。
        if let Err(DomainError::AlreadyExists) = self.deps.intents.insert(&mut tx, &intent).await {
            match self.deps.intents.get(&mut tx, &intent.id).await? {
                Some(existing) => {
                    // 幂等：返回现有状态（awaiting 按统一口径推导；终态带回
                    // result_ref/rejection）。事务无写入，直接释放。
                    let awaiting = self.is_awaiting(&mut tx, &existing).await?;
                    return Ok(result_of(&existing, awaiting));
                }
                None => return Err(AppError::Domain(DomainError::ReplayDetected)),
            }
        }

        // d. 过期双保险（构造时已保证 expires > now，此处覆盖推进间隙越过边界的情形）。
        if !intent.is_replay_safe(now) {
            intent.advance(IntentStatus::Expired)?;
            let resource = deny_resource(&intent);
            self.deps.intents.save(&mut tx, &intent).await?;
            self.audit(&mut tx, &intent, &resource, "deny", now, &[], None).await?;
            return self.commit(tx, result_of(&intent, false)).await;
        }

        // e. schema 基线：payload 为 object 即 Validated（逐动作 Schema 属 handler）。
        intent.advance(IntentStatus::Validated)?;

        // f. 授权段：DID 解析 / Agent 规则 / on_behalf_of 语义 / 能力校验。
        if let Err(e) = self.authorize(&mut tx, &intent, now).await {
            return self.reject_and_commit(tx, intent, e.to_string(), now).await;
        }
        intent.advance(IntentStatus::Authorized)?;

        // g/h. 业务段：SAVEPOINT 内分派 handler。
        self.dispatch_and_finish(tx, intent, now).await
    }

    /// 审批续跑：`approve(intent_id, approver)` 驱动 L3/L4 门后半程。
    pub async fn approve(
        &self,
        intent_id: &IntentId,
        approver: &Did,
    ) -> Result<IntentResult, AppError> {
        let mut tx = self.deps.pool.begin().await.map_err(storage_err)?;
        let now = Utc::now();

        let mut intent = self
            .deps
            .intents
            .get(&mut tx, intent_id)
            .await?
            .ok_or_else(|| AppError::intent_not_found(intent_id.as_ref().to_string()))?;

        if intent.status.is_terminal() {
            return Err(AppError::Domain(DomainError::InvalidInput(format!(
                "意图已终态（{}），无可审批续跑",
                intent.status.as_str()
            ))));
        }
        if !intent.is_replay_safe(now) {
            intent.advance(IntentStatus::Expired)?;
            let resource = deny_resource(&intent);
            self.deps.intents.save(&mut tx, &intent).await?;
            self.audit(&mut tx, &intent, &resource, "deny", now, &[], None).await?;
            return self.commit(tx, result_of(&intent, false)).await;
        }

        let row = self
            .deps
            .approvals
            .find(&mut tx, &intent.id)
            .await?
            .ok_or_else(|| {
                AppError::Domain(DomainError::InvalidInput(format!(
                    "意图 {} 无审批待办",
                    intent.id.as_ref()
                )))
            })?;

        // 已决策：幂等返回当前状态结果。awaiting 按统一口径推导——行已存在，
        // status 仍在门内（如 Proved，并发中途值）→ true；已达 Approved
        // 及之后 / 终态 → false。
        if !row.is_undecided() {
            return Ok(result_of(&intent, awaiting_status(intent.status)));
        }

        // 审批人身份：Phase1 口径 = SubjectKind 匹配 required_role；
        // capability 层面的语义由 required_role 承担（Task 20+ 如需收紧再扩）。
        // 角色不符是**调用方错误**（Unauthorized Err）：不动 intent 状态、
        // 不动 approvals 行——误触不得杀死意图，待正确角色再来审批。
        let approver_doc = self
            .deps
            .identity
            .find_document(&mut tx, approver)
            .await?
            .ok_or_else(|| {
                DomainError::Unauthorized(format!("审批人 DID 文档不存在：{approver}"))
            })?;
        let kind = subject_kind_str(&approver_doc.kind);
        if kind != row.required_role {
            return Err(AppError::Domain(DomainError::Unauthorized(format!(
                "审批人角色不符：要求 `{}`，实际 `{}`（意图不受影响，可由正确角色继续审批）",
                row.required_role, kind
            ))));
        }

        // 决策一次性写入（并发下 0 行 → AlreadyExists = 他者已决策，幂等返回）。
        if let Err(DomainError::AlreadyExists) = self
            .deps
            .approvals
            .mark_decided(&mut tx, &intent.id, approver, now)
            .await
        {
            return Ok(result_of(&intent, awaiting_status(intent.status)));
        }

        // SAVEPOINT 内重跑 handler：handler 查 approvals 已决策 → 过门走后半程。
        self.dispatch_and_finish(tx, intent, now).await
    }

    /// 授权段：actor 文档解析、Agent 挂靠规则、on_behalf_of 语义、能力校验。
    ///
    /// Phase1 口径：**任何 actor（含企业主体）都须持有对应能力**——
    /// capabilities_of 对非 agent DID 同样查询（capabilities 表的 agent_did
    /// 列无非 agent 约束）；Task 20+ 再按主体类型放宽。
    async fn authorize(
        &self,
        tx: &mut PgTx,
        intent: &Intent,
        now: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let doc = self
            .deps
            .identity
            .find_document(tx, &intent.actor)
            .await?
            .ok_or_else(|| {
                DomainError::Unauthorized(format!("发起人 DID 文档不存在：{}", intent.actor))
            })?;
        // 结构规则（Agent 必须挂靠且不得嵌套 / 非 Agent 不得挂靠）
        doc.validate()?;

        // Agent 挂靠存在性：parent 必须实际存在（validate 只查字符串形态）。
        if doc.kind == vg_domain::identity::SubjectKind::Agent {
            let parent = doc
                .parent
                .as_ref()
                .expect("validate 已保证 Agent 必有 parent");
            match self.deps.identity.find_document(tx, parent).await? {
                Some(p) if p.kind != vg_domain::identity::SubjectKind::Agent => {}
                _ => {
                    return Err(DomainError::Unauthorized(
                        "智能体的父主体不存在或仍为智能体".into(),
                    ));
                }
            }
        }

        // on_behalf_of 语义：仅 Agent 可代发，且被代理方必须是挂靠 parent。
        // （Task20 的 handler 以 on_behalf_of 做资源归属判定，此处只锁形态。）
        if let Some(ob) = &intent.on_behalf_of {
            let ok = doc.kind == vg_domain::identity::SubjectKind::Agent
                && doc.parent.as_ref() == Some(ob);
            if !ok {
                return Err(DomainError::InvalidInput(format!(
                    "on_behalf_of 必须为发起 Agent 的挂靠主体，实际：{ob}"
                )));
            }
        }

        // 能力校验（查询类动作为 None 跳过）。
        if let Some(cap) = required_capability(intent.action) {
            let caps = self
                .deps
                .identity
                .capabilities_of(tx, &intent.actor)
                .await?;
            vg_domain::identity::assert_allowed(&caps, &cap, now)?;
        }
        Ok(())
    }

    /// 业务段分派 + 收尾（execute 与 approve 共用）。
    ///
    /// SAVEPOINT `handler_sp` 包住 handler.handle：Err 时 ROLLBACK TO
    /// SAVEPOINT 只回滚业务写入，intent 本体照常 reject/save/audit/commit。
    async fn dispatch_and_finish(
        &self,
        mut tx: PgTx,
        mut intent: Intent,
        now: DateTime<Utc>,
    ) -> Result<IntentResult, AppError> {
        let handler = match self.handlers.get(&intent.action) {
            Ok(h) => h,
            // 未注册处理器：与 handler Err 同路径（reject + 审计留痕）
            Err(e) => {
                return self.reject_and_commit(tx, intent, e.to_string(), now).await;
            }
        };

        sqlx::query(&format!("SAVEPOINT {HANDLER_SAVEPOINT}"))
            .execute(&mut *tx)
            .await
            .map_err(storage_err)?;

        let outcome = handler.handle(&self.deps, &mut tx, &mut intent, now).await;

        match outcome {
            Err(e) => {
                // 业务段回滚：只撤销 savepoint 之后的写入，intent/审计保留。
                sqlx::query(&format!("ROLLBACK TO SAVEPOINT {HANDLER_SAVEPOINT}"))
                    .execute(&mut *tx)
                    .await
                    .map_err(storage_err)?;
                self.reject_and_commit(tx, intent, e.to_string(), now).await
            }
            Ok(HandlerOutcome::AwaitingApproval { required_role }) => {
                // 审批门：落未决行，intent 停在 handler 留下的 Approved 前状态。
                self.deps
                    .approvals
                    .upsert_undecided(&mut tx, &intent.id, &required_role)
                    .await?;
                self.deps.intents.save(&mut tx, &intent).await?;
                self.commit(tx, result_of(&intent, true)).await
            }
            Ok(HandlerOutcome::Completed {
                result_ref,
                resource,
                policy,
                proof_id,
            }) => {
                // 收尾正序：当前状态 → Approved → Submitted → Confirmed。
                advance_to_approved(&mut intent)?;
                intent.advance(IntentStatus::Submitted)?;
                intent.confirm(&result_ref)?;
                self.deps.intents.save(&mut tx, &intent).await?;
                self.audit(&mut tx, &intent, &resource, "allow", now, &policy, proof_id.as_ref())
                    .await?;
                self.commit(tx, result_of(&intent, false)).await
            }
        }
    }

    /// 拒绝并提交审计（intent 保留为终态 Rejected）。
    ///
    /// 调用前提：业务写入已在 savepoint 回滚（或本就无业务写入——授权段失败）。
    async fn reject_and_commit(
        &self,
        mut tx: PgTx,
        mut intent: Intent,
        reason: String,
        now: DateTime<Utc>,
    ) -> Result<IntentResult, AppError> {
        let resource = deny_resource(&intent);
        intent.reject(reason)?;
        self.deps.intents.save(&mut tx, &intent).await?;
        self.audit(&mut tx, &intent, &resource, "deny", now, &[], None).await?;
        self.commit(tx, result_of(&intent, false)).await
    }

    /// 统一口径：`approvals 行存在 && 状态未达 Approved 且非终态`。
    async fn is_awaiting(&self, tx: &mut PgTx, intent: &Intent) -> Result<bool, AppError> {
        Ok(self
            .deps
            .approvals
            .find(tx, &intent.id)
            .await?
            .is_some_and(|_| awaiting_status(intent.status)))
    }

    /// 审计条目写入（action 词表 = IntentAction snake_case；result ∈ allow|deny）。
    ///
    /// **policy 口径（Task 20 起）**：`policy_id` / `policy_version` 取
    /// handler 携带的 enforced 策略版本**最后一条**（多条适用策略全部执行时，
    /// 审计行记录终裁版本；空集合 → 两列皆 None）。deny 路径策略尚未执行，
    /// 恒传空集合。
    #[allow(clippy::too_many_arguments)] // 审计上下文全量透传，参数即审计字段清单
    async fn audit(
        &self,
        tx: &mut PgTx,
        intent: &Intent,
        resource: &str,
        result: &str,
        now: DateTime<Utc>,
        policy: &[PolicyVersion],
        proof_id: Option<&ProofId>,
    ) -> Result<(), AppError> {
        // enforced 最后一条为审计口径；(PolicyId, u64) 拆列为 audit 表的两列
        let (policy_id, policy_version) = match policy.last() {
            Some((id, version)) => (Some(id.to_string()), Some(*version as i64)),
            None => (None, None),
        };
        self.deps
            .audit
            .append(
                tx,
                &AuditEntry {
                    actor: intent.actor.clone(),
                    agent: intent.on_behalf_of.clone(),
                    intent_id: Some(intent.id.as_ref().to_string()),
                    action: intent.action.as_str().to_string(),
                    resource: resource.to_string(),
                    policy_id,
                    policy_version,
                    proof_id: proof_id.map(|p| p.to_string()),
                    result: result.to_string(),
                    at: now,
                },
            )
            .await?;
        Ok(())
    }

    /// 提交事务并返回结果（提交失败 = 全部写入丢失，报存储错误）。
    async fn commit(&self, tx: PgTx, result: IntentResult) -> Result<IntentResult, AppError> {
        tx.commit().await.map_err(storage_err)?;
        Ok(result)
    }
}

/// 审批门等待判定（状态侧谓词，统一口径的 `awaiting_approval` 半边）：
/// 非终态且未达 Approved（Created..=Proved）即视为仍在门内。
///
/// 另一半边是「approvals 行存在」——两侧都成立才置 `awaiting_approval`
/// （行未决的常规情形天然满足；行已决策但续跑事务未提交的并发中途值
/// 亦为 true，客户端以 `status` 为准）。
fn awaiting_status(status: IntentStatus) -> bool {
    !status.is_terminal() && !matches!(status, IntentStatus::Approved | IntentStatus::Submitted)
}

/// 由 intent 快照拼执行结果。
fn result_of(intent: &Intent, awaiting_approval: bool) -> IntentResult {
    IntentResult {
        intent_id: intent.id.as_ref().to_string(),
        status: intent.status,
        risk: intent.risk,
        result_ref: intent.result_ref.clone(),
        rejection: intent.rejection.clone(),
        awaiting_approval,
    }
}

/// 拒绝路径的审计资源：payload 的 `subject` 字段，缺省以动作名兜底。
///
/// Task 20 起 subject 的规范形为 [`SubjectRef`] 的对象形
/// `{"type":"batch","id":"bt-1"}`——此处编码为 `batch:bt-1`（与 infra
/// `encode_subject` 同一口径）；兼容旧的纯字符串形。
fn deny_resource(intent: &Intent) -> String {
    match intent.payload.get("subject") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(map)) => {
            let kind = map.get("type").and_then(Value::as_str);
            let id = map.get("id").and_then(Value::as_str);
            match (kind, id) {
                (Some(k), Some(i)) if !k.is_empty() && !i.is_empty() => format!("{k}:{i}"),
                _ => intent.action.as_str().to_string(),
            }
        }
        _ => intent.action.as_str().to_string(),
    }
}

/// SubjectKind 的 snake_case 文本（与 dids 表 CHECK 白名单口径一致）。
///
/// 前提锁定：`SubjectKind` 全部为 unit variant（无携带数据的变体），serde
/// 序列化必产 `Value::String`。`debug_assert` 把该前提固化为哨兵——若未来
/// 引入带数据变体（序列化为 map 等），测试构建下在此先报警，先于生产
/// `unreachable` 崩溃暴露。
fn subject_kind_str(kind: &vg_domain::identity::SubjectKind) -> String {
    let v = serde_json::to_value(kind);
    debug_assert!(
        matches!(&v, Ok(Value::String(_))),
        "SubjectKind 序列化非字符串：{v:?}（unit-variant 前提被打破）"
    );
    match v {
        Ok(Value::String(s)) => s,
        _ => unreachable!("SubjectKind 为 unit variant，序列化必为字符串"),
    }
}

/// sqlx 原生错误 → 领域存储错误（engine 直接面对 BEGIN/SAVEPOINT 等 SQL）。
fn storage_err(e: sqlx::Error) -> AppError {
    AppError::Domain(DomainError::Storage(e.to_string()))
}

/// 从当前状态走合法边到 Approved（无需证明的从 PolicyChecked 直达，
/// 需要证明的由 handler 推进到 Proved 后在此续走）。
fn advance_to_approved(intent: &mut Intent) -> Result<(), DomainError> {
    use IntentStatus::*;
    match intent.status {
        Authorized => {
            intent.advance(PolicyChecked)?;
            intent.advance(Approved)
        }
        PolicyChecked | Proved => intent.advance(Approved),
        ProofRequired => {
            intent.advance(Proved)?;
            intent.advance(Approved)
        }
        Approved => Ok(()),
        other => Err(DomainError::InvalidTransition {
            from: other.to_string(),
            to: Approved.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use vg_domain::identity::{
        assert_allowed, ports::IdentityRepository, Capability, DidDocument, SubjectKind,
        VerificationMethod,
    };
    use vg_domain::intent::ports::IntentRepository;
    use vg_domain::ports::{CircuitSpec, NoteHasher, ProofProver, Witness};
    use vg_domain::shared::{DomainError, Hash32};
    use vg_infra_pg::{
        InProcessLedger, PgApprovalsStore, PgAuditWriter, PgCommodityRepo, PgCredentialRepo,
        PgIdentityRepo, PgIntentRepository, PgLifecycleRepo, PgOutbox, PgOwnershipRepo,
        PgPolicyRepository, PgProofStore,
    };

    // ---- 测试桩：prover / hasher ----

    struct StubProver;
    #[async_trait]
    impl ProofProver for StubProver {
        async fn prove(
            &self,
            circuit: &CircuitSpec,
            _witness: &Witness,
        ) -> Result<vg_domain::ports::ProofBundle, DomainError> {
            Ok(vg_domain::ports::ProofBundle {
                circuit_id: circuit.id.clone(),
                version: circuit.version,
                proof: vec![0x42],
                publics: circuit.public_inputs.clone(),
            })
        }
        fn verify(&self, _b: &vg_domain::ports::ProofBundle) -> Result<bool, DomainError> {
            Ok(true)
        }
    }

    struct StubHasher;
    impl NoteHasher for StubHasher {
        fn note_commitment(&self, parts: &[[u8; 32]]) -> Hash32 {
            Hash32::keccak(&parts.concat())
        }
    }

    // ---- 测试桩 handler ----

    /// L2 直通桩：推进 PolicyChecked 后返回 Completed（计数器观测重复调用）。
    struct CountingHandler {
        calls: AtomicUsize,
    }
    #[async_trait]
    impl IntentHandler for CountingHandler {
        fn action(&self) -> IntentAction {
            IntentAction::CreateBatch
        }
        async fn handle(
            &self,
            _deps: &AppDeps,
            _tx: &mut PgTx,
            intent: &mut Intent,
            _now: DateTime<Utc>,
        ) -> Result<HandlerOutcome, DomainError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            intent.advance(IntentStatus::PolicyChecked)?;
            Ok(HandlerOutcome::Completed {
                result_ref: "stub:batch-ref-1".into(),
                resource: "batch:stub-1".into(),
                policy: vec![],
                proof_id: None,
            })
        }
    }

    /// L3 审批门桩：推进到 Proved 后查 approvals——未决策 AwaitingApproval，
    /// 已决策 Completed。
    struct GatedTransferHandler {
        calls: AtomicUsize,
    }
    #[async_trait]
    impl IntentHandler for GatedTransferHandler {
        fn action(&self) -> IntentAction {
            IntentAction::TransferProduct
        }
        async fn handle(
            &self,
            deps: &AppDeps,
            tx: &mut PgTx,
            intent: &mut Intent,
            _now: DateTime<Utc>,
        ) -> Result<HandlerOutcome, DomainError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            // 续跑幂等：首跑从 Authorized 起步推进；门内二次进入时状态
            // 已在 Proved，不重推（真实 handler 的既有段亦不重执行）。
            if intent.status == IntentStatus::Authorized {
                intent.advance(IntentStatus::PolicyChecked)?;
                intent.advance(IntentStatus::ProofRequired)?;
                intent.advance(IntentStatus::Proved)?;
            }
            let row = deps.approvals.find(tx, &intent.id).await?;
            match row.as_ref().map(|r| r.is_undecided()) {
                Some(true) | None => Ok(HandlerOutcome::AwaitingApproval {
                    required_role: "regulator".into(),
                }),
                Some(false) => Ok(HandlerOutcome::Completed {
                    result_ref: "stub:transfer-ref-1".into(),
                    resource: "batch:stub-t".into(),
                    policy: vec![],
                    proof_id: None,
                }),
            }
        }
    }

    // ---- fixture ----

    fn did(s: &str) -> Did {
        Did::parse(s).unwrap()
    }

    fn doc(did: Did, kind: SubjectKind, parent: Option<Did>) -> DidDocument {
        DidDocument {
            did: did.clone(),
            kind,
            methods: vec![VerificationMethod::new(
                "k-0",
                vg_domain::identity::KeyType::Secp256k1,
                Hash32::keccak(b"pk"),
                did,
            )],
            parent,
            jurisdiction: Some("CN".into()),
            created_at: Utc::now(),
        }
    }

    /// 组装 AppDeps（全部真实 Pg 仓储 + 桩 prover/hasher + InProcessLedger）。
    fn deps(pool: sqlx::PgPool) -> AppDeps {
        AppDeps {
            pool: pool.clone(),
            identity: Arc::new(PgIdentityRepo),
            credentials: Arc::new(PgCredentialRepo),
            commodity: Arc::new(PgCommodityRepo),
            ownership: Arc::new(PgOwnershipRepo),
            lifecycle: Arc::new(PgLifecycleRepo),
            policies: Arc::new(PgPolicyRepository),
            intents: Arc::new(PgIntentRepository),
            proofs: Arc::new(PgProofStore),
            audit: Arc::new(PgAuditWriter),
            outbox: Arc::new(PgOutbox),
            approvals: Arc::new(PgApprovalsStore),
            ledger: Arc::new(InProcessLedger::new(pool)),
            prover: Arc::new(StubProver),
            hasher: Arc::new(StubHasher),
        }
    }

    fn raw(id: &str, action: IntentAction, actor: &Did, nonce: u64) -> RawIntent {
        RawIntent {
            id: IntentId::new(id),
            action,
            actor: actor.clone(),
            on_behalf_of: None,
            payload: serde_json::json!({"subject": "batch:stub-1", "qty": 1}),
            nonce,
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }
    }

    /// 前置身份：企业主体 + 能力授予 +（可选）监管审批人。
    async fn seed_actor(
        pool: &sqlx::PgPool,
        actor: &Did,
        cap: Option<CapabilityAction>,
        regulator: bool,
    ) {
        let mut tx = pool.begin().await.unwrap();
        let identity = PgIdentityRepo;
        let kind = if regulator {
            SubjectKind::Regulator
        } else {
            SubjectKind::Enterprise
        };
        identity
            .save_document(&mut tx, &doc(actor.clone(), kind, None))
            .await
            .unwrap();
        let grantor = did("did:vg:user:grantor-19");
        if !regulator {
            identity
                .save_document(
                    &mut tx,
                    &doc(grantor.clone(), SubjectKind::Enterprise, None),
                )
                .await
                .unwrap();
            if let Some(a) = cap {
                identity
                    .grant_capability(
                        &mut tx,
                        &Capability::new(actor.clone(), a, grantor, None).unwrap(),
                    )
                    .await
                    .unwrap();
            }
        }
        tx.commit().await.unwrap();
    }

    /// audit_events 计数（SQL 断言用）。
    async fn audit_count(pool: &sqlx::PgPool, intent_id: &str, result: &str) -> i64 {
        let row: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM audit_events WHERE intent_id = $1 AND result = $2",
        )
        .bind(intent_id)
        .bind(result)
        .fetch_one(pool)
        .await
        .unwrap();
        row.0
    }

    /// 意图状态直查（SQL 断言用）。
    async fn intent_status(pool: &sqlx::PgPool, id: &str) -> String {
        let row: (String,) = sqlx::query_as("SELECT status FROM intents WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
        row.0
    }

    fn engine(deps: &AppDeps, handlers: Vec<Arc<dyn IntentHandler>>) -> IntentEngine {
        let mut map = HandlerMap::new();
        for h in handlers {
            map.register(h);
        }
        IntentEngine::new(deps.clone(), map)
    }

    // ---- 测试 ----

    /// 幂等（plan 必测）：同 RawIntent 两次 execute → IntentResult 深相等
    /// （Confirmed 同 result_ref），handler 只被调用一次。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn idempotent_resubmit_returns_same_result(pool: sqlx::PgPool) {
        let actor = did("did:vg:user:ent-idem");
        seed_actor(&pool, &actor, Some(CapabilityAction::CreateBatch), false).await;

        let handler = Arc::new(CountingHandler {
            calls: AtomicUsize::new(0),
        });
        let engine = engine(&deps(pool.clone()), vec![handler.clone()]);

        let raw = raw("it-idem-1", IntentAction::CreateBatch, &actor, 1);
        let first = engine
            .execute(raw.clone())
            .await
            .expect("首次执行应 Confirmed");
        assert_eq!(first.status, IntentStatus::Confirmed);
        assert_eq!(first.result_ref.as_deref(), Some("stub:batch-ref-1"));
        assert!(!first.awaiting_approval);
        assert_eq!(first.risk, RiskLevel::L2);

        let second = engine
            .execute(raw)
            .await
            .expect("重复提交应幂等返回（而非报错）");
        assert_eq!(first, second, "两次 IntentResult 应深相等");
        assert_eq!(
            handler.calls.load(Ordering::SeqCst),
            1,
            "handler 只执行一次"
        );
        assert_eq!(audit_count(&pool, "it-idem-1", "allow").await, 1);
    }

    /// 无 Capability（plan 必测）：status=Rejected、rejection 含原因、
    /// audit deny 行存在、handler 计数为 0（授权段前置拦截）。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn missing_capability_rejects_without_dispatching(pool: sqlx::PgPool) {
        let actor = did("did:vg:user:ent-nocap");
        seed_actor(&pool, &actor, None, false).await;

        let handler = Arc::new(CountingHandler {
            calls: AtomicUsize::new(0),
        });
        let engine = engine(&deps(pool.clone()), vec![handler.clone()]);

        let result = engine
            .execute(raw("it-nocap-1", IntentAction::CreateBatch, &actor, 1))
            .await
            .expect("无能力是业务拒绝（Rejected 结果），非 Err");
        assert_eq!(result.status, IntentStatus::Rejected);
        assert!(result
            .rejection
            .as_deref()
            .is_some_and(|r| r.contains("能力")));
        assert!(!result.awaiting_approval);
        assert_eq!(
            handler.calls.load(Ordering::SeqCst),
            0,
            "授权失败不得分派 handler"
        );
        assert_eq!(audit_count(&pool, "it-nocap-1", "deny").await, 1);

        // 落库断言：意图保留为 rejected 终态
        assert_eq!(intent_status(&pool, "it-nocap-1").await, "rejected");
    }

    /// L3 审批门（plan 必测）：execute 停在 Proved + awaiting；
    /// approve 后 handler 二次执行 → Confirmed、审批行已决策、audit allow。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn l3_gate_pauses_then_approve_confirms(pool: sqlx::PgPool) {
        let actor = did("did:vg:user:ent-l3");
        let regulator = did("did:vg:user:reg-l3");
        seed_actor(
            &pool,
            &actor,
            Some(CapabilityAction::TransferOwnership),
            false,
        )
        .await;
        seed_actor(&pool, &regulator, None, true).await;

        let handler = Arc::new(GatedTransferHandler {
            calls: AtomicUsize::new(0),
        });
        let engine = engine(&deps(pool.clone()), vec![handler.clone()]);

        // 第一次：停在审批门
        let r = raw("it-l3-1", IntentAction::TransferProduct, &actor, 1);
        let result = engine
            .execute(r.clone())
            .await
            .expect("审批门路径应正常返回");
        assert_eq!(
            result.status,
            IntentStatus::Proved,
            "L3 带证明动作停在 Proved"
        );
        assert!(!result.status.is_terminal());
        assert!(result.awaiting_approval);
        assert_eq!(result.risk, RiskLevel::L3);
        assert_eq!(handler.calls.load(Ordering::SeqCst), 1);

        // approvals 行未决存在
        let mut tx = pool.begin().await.unwrap();
        let row = PgApprovalsStore
            .find(&mut tx, &IntentId::new("it-l3-1"))
            .await
            .unwrap()
            .expect("审批待办行应存在");
        assert_eq!(row.required_role, "regulator");
        assert!(row.is_undecided());
        tx.commit().await.unwrap();

        // 审批续跑：Confirmed
        let approved = engine
            .approve(&IntentId::new("it-l3-1"), &regulator)
            .await
            .expect("审批续跑应 Confirmed");
        assert_eq!(approved.status, IntentStatus::Confirmed);
        assert_eq!(approved.result_ref.as_deref(), Some("stub:transfer-ref-1"));
        assert!(!approved.awaiting_approval);
        assert_eq!(
            handler.calls.load(Ordering::SeqCst),
            2,
            "handler 二次执行过门"
        );

        // approvals 行已决策 + audit allow
        let mut tx = pool.begin().await.unwrap();
        let row = PgApprovalsStore
            .find(&mut tx, &IntentId::new("it-l3-1"))
            .await
            .unwrap()
            .expect("审批待办行应存在");
        assert!(!row.is_undecided());
        assert_eq!(row.decided_by.as_deref(), Some("did:vg:user:reg-l3"));
        tx.commit().await.unwrap();
        assert_eq!(audit_count(&pool, "it-l3-1", "allow").await, 1);

        // 幂等重放（已 Confirmed 终态，统一口径第 2 情形）：同 id 重提交
        // 返回当前快照，awaiting=false（终态且已达 Approved）。
        let replay = engine
            .execute(r)
            .await
            .expect("Confirmed 后重提交应幂等返回");
        assert_eq!(replay.status, IntentStatus::Confirmed);
        assert!(!replay.awaiting_approval, "终态不得再标等待审批");
    }

    /// awaiting 统一口径第 3 情形（并发中途值）：status 停在门内（Proved）
    /// 而 approvals 行**已决策**（他者续跑事务尚未提交/中途失败）——
    /// approve 幂等返回 true（仍标等待中，客户端以 status 为准），
    /// 且 handler 不被重跑。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn awaiting_flag_midvalue_decided_row_still_true(pool: sqlx::PgPool) {
        let actor = did("did:vg:user:ent-mid");
        let regulator = did("did:vg:user:reg-mid");
        seed_actor(
            &pool,
            &actor,
            Some(CapabilityAction::TransferOwnership),
            false,
        )
        .await;
        seed_actor(&pool, &regulator, None, true).await;

        let handler = Arc::new(GatedTransferHandler {
            calls: AtomicUsize::new(0),
        });
        let engine = engine(&deps(pool.clone()), vec![handler.clone()]);
        engine
            .execute(raw("it-mid-1", IntentAction::TransferProduct, &actor, 1))
            .await
            .unwrap();

        // 手工把 approvals 行置为已决策（模拟他者 mark 后续跑未提交的中途值）
        let mut tx = pool.begin().await.unwrap();
        let approver = did("did:vg:user:reg-mid");
        PgApprovalsStore
            .mark_decided(&mut tx, &IntentId::new("it-mid-1"), &approver, Utc::now())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(intent_status(&pool, "it-mid-1").await, "proved");

        // approve 幂等路径：行已决策、status 仍在门内 → awaiting=true
        let result = engine
            .approve(&IntentId::new("it-mid-1"), &regulator)
            .await
            .expect("已决策行的 approve 应幂等返回而非报错");
        assert_eq!(result.status, IntentStatus::Proved);
        assert!(result.awaiting_approval, "门内中途值仍应标等待审批");
        assert_eq!(
            handler.calls.load(Ordering::SeqCst),
            1,
            "已决策幂等路径不得重跑 handler"
        );
    }

    /// 审批人角色不符：Err(Unauthorized) 且**不消耗审批**——intent 仍
    /// Proved、approvals 行仍未决、handler 不被重跑；正确角色随后仍可
    /// 审批通过（误触不得杀死意图）。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn approve_with_wrong_role_errors_without_consuming(pool: sqlx::PgPool) {
        let actor = did("did:vg:user:ent-l3w");
        let outsider = did("did:vg:user:ent-other");
        let regulator = did("did:vg:user:reg-l3w");
        seed_actor(
            &pool,
            &actor,
            Some(CapabilityAction::TransferOwnership),
            false,
        )
        .await;
        seed_actor(&pool, &outsider, None, false).await;
        seed_actor(&pool, &regulator, None, true).await;

        let handler = Arc::new(GatedTransferHandler {
            calls: AtomicUsize::new(0),
        });
        let engine = engine(&deps(pool.clone()), vec![handler.clone()]);
        let result = engine
            .execute(raw("it-l3w-1", IntentAction::TransferProduct, &actor, 1))
            .await
            .unwrap();
        assert!(result.awaiting_approval);

        // 错误角色：Err(Unauthorized)，非业务 Rejected 结果
        match engine
            .approve(&IntentId::new("it-l3w-1"), &outsider)
            .await
        {
            Err(AppError::Domain(DomainError::Unauthorized(msg))) => {
                assert!(msg.contains("角色不符"), "实际消息：{msg}");
            }
            other => panic!("角色不符应报 Err(Unauthorized)，实际：{other:?}"),
        }

        // 不动 intent、不动 approvals 行、handler 不重跑、无 deny 审计
        assert_eq!(intent_status(&pool, "it-l3w-1").await, "proved");
        let mut tx = pool.begin().await.unwrap();
        let row = PgApprovalsStore
            .find(&mut tx, &IntentId::new("it-l3w-1"))
            .await
            .unwrap()
            .expect("审批待办行应存在");
        assert!(row.is_undecided(), "角色不符不得消耗审批（行仍未决）");
        tx.commit().await.unwrap();
        assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
        assert_eq!(audit_count(&pool, "it-l3w-1", "deny").await, 0);

        // 正确角色随后仍走通：Confirmed
        let approved = engine
            .approve(&IntentId::new("it-l3w-1"), &regulator)
            .await
            .expect("正确角色审批应 Confirmed");
        assert_eq!(approved.status, IntentStatus::Confirmed);
        assert!(!approved.awaiting_approval);
    }

    /// nonce 冲突：同 actor 同 nonce 异 id 二次 execute → ReplayDetected。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn nonce_clash_reports_replay(pool: sqlx::PgPool) {
        let actor = did("did:vg:user:ent-replay");
        seed_actor(&pool, &actor, Some(CapabilityAction::CreateBatch), false).await;

        let engine = engine(
            &deps(pool),
            vec![Arc::new(CountingHandler {
                calls: AtomicUsize::new(0),
            })],
        );
        let first = engine
            .execute(raw("it-replay-1", IntentAction::CreateBatch, &actor, 7))
            .await
            .expect("首次应成功");
        assert_eq!(first.status, IntentStatus::Confirmed);

        // 同 nonce 异 id：insert 0 行 + get None → ReplayDetected
        match engine
            .execute(raw("it-replay-2", IntentAction::CreateBatch, &actor, 7))
            .await
        {
            Err(AppError::Domain(DomainError::ReplayDetected)) => {}
            other => panic!("nonce 冲突应报 ReplayDetected，实际：{other:?}"),
        }
    }

    /// Agent 路径：agent DID + parent enterprise + capability → Authorized
    /// 过（on_behalf_of=parent），全链 Confirmed。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn agent_on_behalf_of_parent_confirms(pool: sqlx::PgPool) {
        let parent = did("did:vg:user:ent-parent");
        let agent = did("did:vg:agent:ag-19");
        let grantor = did("did:vg:user:grantor-ag");

        let mut tx = pool.begin().await.unwrap();
        let identity = PgIdentityRepo;
        identity
            .save_document(&mut tx, &doc(parent.clone(), SubjectKind::Enterprise, None))
            .await
            .unwrap();
        identity
            .save_document(
                &mut tx,
                &doc(grantor.clone(), SubjectKind::Enterprise, None),
            )
            .await
            .unwrap();
        identity
            .save_document(
                &mut tx,
                &doc(agent.clone(), SubjectKind::Agent, Some(parent.clone())),
            )
            .await
            .unwrap();
        identity
            .grant_capability(
                &mut tx,
                &Capability::new(agent.clone(), CapabilityAction::CreateBatch, grantor, None)
                    .unwrap(),
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let engine = engine(
            &deps(pool),
            vec![Arc::new(CountingHandler {
                calls: AtomicUsize::new(0),
            })],
        );
        let mut r = raw("it-agent-1", IntentAction::CreateBatch, &agent, 1);
        r.on_behalf_of = Some(parent);
        let result = engine.execute(r).await.expect("Agent 代发应 Confirmed");
        assert_eq!(result.status, IntentStatus::Confirmed);
    }

    /// Agent 的 on_behalf_of 指向非挂靠主体 → InvalidInput 拒绝。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn agent_with_foreign_on_behalf_of_rejected(pool: sqlx::PgPool) {
        let parent = did("did:vg:user:ent-p2");
        let agent = did("did:vg:agent:ag-20");
        let stranger = did("did:vg:user:ent-stranger");
        let grantor = did("did:vg:user:grantor-ag2");

        let mut tx = pool.begin().await.unwrap();
        let identity = PgIdentityRepo;
        for d in [&parent, &stranger, &grantor] {
            identity
                .save_document(&mut tx, &doc(d.clone(), SubjectKind::Enterprise, None))
                .await
                .unwrap();
        }
        identity
            .save_document(
                &mut tx,
                &doc(agent.clone(), SubjectKind::Agent, Some(parent.clone())),
            )
            .await
            .unwrap();
        identity
            .grant_capability(
                &mut tx,
                &Capability::new(agent.clone(), CapabilityAction::CreateBatch, grantor, None)
                    .unwrap(),
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let engine = engine(
            &deps(pool),
            vec![Arc::new(CountingHandler {
                calls: AtomicUsize::new(0),
            })],
        );
        let mut r = raw("it-agent-2", IntentAction::CreateBatch, &agent, 1);
        r.on_behalf_of = Some(stranger);
        let result = engine.execute(r).await.expect("语义违规是 Rejected 结果");
        assert_eq!(result.status, IntentStatus::Rejected);
        assert!(result
            .rejection
            .as_deref()
            .is_some_and(|x| x.contains("on_behalf_of")));
    }

    /// 未注册动作：Rejected（原因含「未注册」）+ audit deny 留痕。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn unregistered_action_rejects(pool: sqlx::PgPool) {
        let actor = did("did:vg:user:ent-unreg");
        seed_actor(
            &pool,
            &actor,
            Some(CapabilityAction::TransferOwnership),
            false,
        )
        .await;

        // 只注册 CreateBatch 处理器；TransferProduct 未注册
        let engine = engine(
            &deps(pool.clone()),
            vec![Arc::new(CountingHandler {
                calls: AtomicUsize::new(0),
            })],
        );
        let result = engine
            .execute(raw("it-unreg-1", IntentAction::TransferProduct, &actor, 1))
            .await
            .expect("未注册动作是业务拒绝（Rejected 结果）");
        assert_eq!(result.status, IntentStatus::Rejected);
        assert!(result
            .rejection
            .as_deref()
            .is_some_and(|r| r.contains("未注册")));
        assert_eq!(audit_count(&pool, "it-unreg-1", "deny").await, 1);
    }

    /// 构造校验失败（过期窗口）：InvalidInput 且 intent 不落库。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn expired_window_rejected_at_construction(pool: sqlx::PgPool) {
        let actor = did("did:vg:user:ent-exp");
        seed_actor(&pool, &actor, Some(CapabilityAction::CreateBatch), false).await;

        let engine = engine(
            &deps(pool.clone()),
            vec![Arc::new(CountingHandler {
                calls: AtomicUsize::new(0),
            })],
        );
        let mut r = raw("it-exp-1", IntentAction::CreateBatch, &actor, 1);
        r.expires_at = Utc::now() - chrono::Duration::hours(1);
        match engine.execute(r).await {
            Err(AppError::Domain(DomainError::InvalidInput(_))) => {}
            other => panic!("过期窗口应在构造层拒绝，实际：{other:?}"),
        }
        // 未落库：intents 无行
        let row: (i64,) = sqlx::query_as("SELECT count(*) FROM intents WHERE id = 'it-exp-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.0, 0);
    }

    /// approve 的前置拒绝：不存在 → IntentNotFound；无审批待办 → InvalidInput；
    /// 终态 → InvalidInput。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn approve_precondition_failures(pool: sqlx::PgPool) {
        let actor = did("did:vg:user:ent-ap");
        let regulator = did("did:vg:user:reg-ap");
        seed_actor(&pool, &actor, Some(CapabilityAction::CreateBatch), false).await;
        seed_actor(&pool, &regulator, None, true).await;

        let engine = engine(
            &deps(pool.clone()),
            vec![Arc::new(CountingHandler {
                calls: AtomicUsize::new(0),
            })],
        );

        match engine.approve(&IntentId::new("it-none"), &regulator).await {
            Err(AppError::IntentNotFound(_)) => {}
            other => panic!("不存在的意图应报 IntentNotFound，实际：{other:?}"),
        }

        // Confirmed 终态：无待办路径先被终态检查拦截
        engine
            .execute(raw("it-ap-1", IntentAction::CreateBatch, &actor, 1))
            .await
            .unwrap();
        match engine.approve(&IntentId::new("it-ap-1"), &regulator).await {
            Err(AppError::Domain(DomainError::InvalidInput(_))) => {}
            other => panic!("终态意图 approve 应报 InvalidInput，实际：{other:?}"),
        }

        // 非终态但无审批待办：手工构造一个 Authorized 状态的 intent 落库
        // （不经 execute，故不产生 approvals 行），approve 应报
        // InvalidInput（消息含「无审批待办」）。
        let mut intent = Intent::new(
            IntentId::new("it-ap-2"),
            IntentAction::CreateBatch,
            actor.clone(),
            None,
            serde_json::json!({"subject": "batch:x", "qty": 1}),
            99,
            Utc::now(),
            Utc::now() + chrono::Duration::hours(1),
        )
        .unwrap();
        intent.advance(IntentStatus::Validated).unwrap();
        intent.advance(IntentStatus::Authorized).unwrap();
        let mut tx = pool.begin().await.unwrap();
        PgIntentRepository
            .insert(&mut tx, &intent)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        match engine.approve(&IntentId::new("it-ap-2"), &regulator).await {
            Err(AppError::Domain(DomainError::InvalidInput(msg))) => {
                assert!(msg.contains("无审批待办"), "实际消息：{msg}");
            }
            other => panic!("无审批待办应报 InvalidInput（无审批待办），实际：{other:?}"),
        }
    }

    /// handler 业务段 Err：业务写入回滚（savepoint）、intent=Rejected 保留、
    /// 审计 deny。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn handler_error_rolls_back_business_and_keeps_intent(pool: sqlx::PgPool) {
        use vg_domain::events::DomainEvent;
        use vg_domain::shared::{BatchId, ProductId};
        let actor = did("did:vg:user:ent-err");
        seed_actor(&pool, &actor, Some(CapabilityAction::CreateBatch), false).await;

        /// 失败桩：先在**事务内**写一行业务数据（outbox 事件，随 tx 提交/
        /// 回滚），再报业务错误——验证 ROLLBACK TO SAVEPOINT 撤销的是
        /// 事务内业务写入。
        struct FailingHandler;
        #[async_trait]
        impl IntentHandler for FailingHandler {
            fn action(&self) -> IntentAction {
                IntentAction::CreateBatch
            }
            async fn handle(
                &self,
                deps: &AppDeps,
                tx: &mut PgTx,
                intent: &mut Intent,
                _now: DateTime<Utc>,
            ) -> Result<HandlerOutcome, DomainError> {
                intent.advance(IntentStatus::PolicyChecked)?;
                // 事务内业务写入：outbox 追加（INSERT 走引擎事务，受
                // SAVEPOINT 保护）。
                deps.outbox
                    .append(
                        tx,
                        "intent:it-err-1",
                        &DomainEvent::BatchCreated {
                            batch: BatchId::new("bt-err-biz"),
                            product: ProductId::new("pd-err"),
                            quantity: 1,
                            producer: intent.actor.clone(),
                        },
                    )
                    .await?;
                Err(DomainError::PolicyViolated("数量超限".into()))
            }
        }

        let engine = engine(&deps(pool.clone()), vec![Arc::new(FailingHandler)]);
        let result = engine
            .execute(raw("it-err-1", IntentAction::CreateBatch, &actor, 1))
            .await
            .expect("业务失败是业务拒绝（Rejected 结果），非 Err");
        assert_eq!(result.status, IntentStatus::Rejected);
        assert!(result
            .rejection
            .as_deref()
            .is_some_and(|r| r.contains("数量超限")));
        assert_eq!(intent_status(&pool, "it-err-1").await, "rejected");
        assert_eq!(audit_count(&pool, "it-err-1", "deny").await, 1);
        // savepoint 真实回滚断言：事务内业务写入（outbox 事件）被 ROLLBACK
        // TO SAVEPOINT 撤销，执行后不落任何行。
        let biz: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM domain_events WHERE aggregate = 'intent:it-err-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(biz.0, 0, "事务内业务写入应被 savepoint 回滚撤销");
    }

    /// awaiting_status 谓词穷举：门内（Created..=Proved）true；
    /// Approved 及之后 / 终态 false。
    #[test]
    fn awaiting_status_covers_all_statuses() {
        use IntentStatus::*;
        for s in [Created, Validated, Authorized, PolicyChecked, ProofRequired, Proved] {
            assert!(awaiting_status(s), "{s:?} 应视为门内");
        }
        for s in [Approved, Submitted, Confirmed, Rejected, Expired, Cancelled] {
            assert!(!awaiting_status(s), "{s:?} 不得视为门内");
        }
    }

    /// 映射表穷举：required_capability 覆盖全部 13 动作且与文档表一致。
    #[test]
    fn required_capability_covers_all_actions() {
        use vg_domain::intent::IntentAction::*;
        let expected = |a: IntentAction| match a {
            CreateBatch | SplitBatch | MergeBatch | TransformBatch | CreateItem => {
                Some(CapabilityAction::CreateBatch)
            }
            TransferProduct => Some(CapabilityAction::TransferOwnership),
            UpdateCustody => Some(CapabilityAction::UpdateCustody),
            IssueCredential => Some(CapabilityAction::IssueCredential),
            RevokeCredential => Some(CapabilityAction::RevokeCredential),
            ComplianceCheck | SubmitStateRoot => None,
            ShieldedTransfer => Some(CapabilityAction::SubmitShieldedTx),
            MassRecall => Some(CapabilityAction::MassRecall),
        };
        for a in IntentAction::ALL {
            assert_eq!(required_capability(a), expected(a), "{a:?} 映射不符");
        }
    }

    /// 能力哨兵：assert_allowed 在引擎授权段按同一口径工作（编译期形状锁定）。
    #[test]
    fn capability_assert_shape() {
        let caps = vec![Capability::new(
            did("did:vg:agent:ag-x"),
            CapabilityAction::CreateBatch,
            did("did:vg:user:ent-x"),
            None,
        )
        .unwrap()];
        assert_allowed(&caps, &CapabilityAction::CreateBatch, Utc::now()).unwrap();
    }
}
