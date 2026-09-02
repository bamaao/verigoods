//! 公开转移与保管处理器：TransferProduct（L3）/ UpdateCustody。
//!
//! - **所有权 / 保管分离**：transfer 只动 `OwnershipState` 与转移流水，
//!   custody 联动是可选副作用；UpdateCustody 只动 `CustodyState`，
//!   不触碰所有权（Phase1 保管**不上链**，无锚定）；
//! - **悬挂锚契约**：`ledger.anchor(LedgerItem::Transfer)` 是
//!   TransferProduct 的**最后一个不可逆步骤**——此前全部业务校验
//!   （policy / 状态机 / 领域转移规则）与落库（save / record_transfer /
//!   lifecycle / custody / outbox）必须已完成；
//! - **幂等键派生**：转移记录 ID = `tr:<intent_id>`（仓储按 record_id
//!   唯一去重），生命周期事件 ID = `lce:<intent_id>`（append 幂等）。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use vg_domain::events::DomainEvent;
use vg_domain::intent::{Intent, IntentAction, IntentStatus};
use vg_domain::lifecycle::LifecycleState;
use vg_domain::ownership::{CustodyReason, CustodyState, CustodyUpdate};
use vg_domain::ports::LedgerItem;
use vg_domain::shared::{Did, DomainError, SubjectRef};

use crate::deps::{AppDeps, PgTx};
use crate::handlers::{
    effective_principal, enforce_transition_policy, jurisdiction_of, parse_payload,
    product_category_of, record_lifecycle_transition, require_owner, subject_label,
};
use crate::intent_engine::{HandlerOutcome, IntentHandler};

/// TransferProduct（公开转移）载荷。
///
/// JSON Schema（`deny_unknown_fields`）：
///
/// ```json
/// {
///   "subject":      {"type": "batch", "id": "bt-001"},
///   "to":           "did:vg:user:retailer",
///   "c2c":          false,
///   "lifecycle_to": "available",                     // 可选
///   "custody":      {"to": "did:vg:user:retailer",   // 可选联动
///                    "reason": "warehouse_in"}
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferPayload {
    /// 转移客体（批次或单品，须已建所有权档案）。
    subject: SubjectRef,
    /// 受让方 DID。
    to: Did,
    /// 是否跨企业（company-to-company）转移。
    c2c: bool,
    /// 可选：转移伴随的生命周期迁移。
    lifecycle_to: Option<LifecycleState>,
    /// 可选：转移伴随的保管变更（如零售商入仓）。
    custody: Option<CustodySpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodySpec {
    /// 新保管人。
    to: Did,
    /// 变更原因（serde 值即领域枚举 snake_case：`ship` / `warehouse_in` /
    /// `warehouse_out` / `handover`）。
    reason: CustodyReason,
}

/// 公开转移处理器（L3）。
///
/// 管道：所有权授权闸门（effective principal == 当前 owner，未建档 →
/// InvalidInput、越权 → Unauthorized）→ 可选 lifecycle 迁移的
/// policy 检核（辖区 = **转移前 owner** 的辖区，凭证 = 转移前 owner 的
/// VC）→ `OwnershipState::transfer`（自转/溢出领域校验）→ save +
/// `record_transfer`（幂等键 `tr:<intent_id>`）→ 可选 lifecycle 事件 +
/// 聚合状态回写 → 可选 custody 联动 → outbox → **`ledger.anchor`（最后）**。
pub struct TransferPublicHandler;

#[async_trait]
impl IntentHandler for TransferPublicHandler {
    fn action(&self) -> IntentAction {
        IntentAction::TransferProduct
    }

    async fn handle(
        &self,
        deps: &AppDeps,
        tx: &mut PgTx,
        intent: &mut Intent,
        now: DateTime<Utc>,
    ) -> Result<HandlerOutcome, DomainError> {
        let payload: TransferPayload = parse_payload(intent)?;

        // 授权闸门：effective principal（on_behalf_of 优先）必须是当前
        // owner——能力校验（engine 段）只证明"可发起转移"，不证明"可转
        // 这一件"；通过则返回值即转移前 owner。
        let from_owner = require_owner(deps, tx, intent, &payload.subject).await?;
        let mut ownership = deps
            .ownership
            .get(tx, &payload.subject)
            .await?
            .ok_or_else(|| {
                DomainError::InvalidInput(format!(
                    "主体 {} 尚未建立所有权档案，不可转移",
                    subject_label(&payload.subject)
                ))
            })?;

        // 可选生命周期迁移：policy（辖区/凭证均取转移前 owner）→ 状态机。
        // 当前状态取事件日志终态；无任何事件的建档批次退回 Created
        // （建档不是迁移，批次档案 state 字段与事件日志同源）。
        let mut enforced = Vec::new();
        let mut transition: Option<(LifecycleState, LifecycleState)> = None;
        if let Some(to_state) = payload.lifecycle_to {
            // 事件日志为真相来源；无事件 = 建档态 Created（建档不是迁移，
            // 批次档案 state 字段与事件日志同源）。
            let from_state = deps
                .lifecycle
                .current_state(tx, &payload.subject)
                .await?
                .unwrap_or(LifecycleState::Created);
            let jurisdiction =
                jurisdiction_of(deps, tx, &from_owner, "转移前所有者").await?;
            let category = product_category_of(deps, tx, &payload.subject).await?;
            enforced = enforce_transition_policy(
                deps,
                tx,
                &jurisdiction,
                &category,
                &from_owner,
                from_state,
                to_state,
                now,
            )
            .await?;
            transition = Some((from_state, to_state));
        }

        // ---- 落库段（悬挂锚契约：以下全部可被 savepoint 回滚）----
        let mut record = ownership.transfer(&payload.to, payload.c2c, now)?;
        // 幂等键改派 intent：同 intent 重放/续跑不双计（仓储按 id 去重）
        record.id = format!("tr:{}", intent.id.as_ref());
        deps.ownership.save(tx, &ownership).await?;
        deps.ownership.record_transfer(tx, &record).await?;

        if let Some((from_state, to_state)) = transition {
            record_lifecycle_transition(
                deps,
                tx,
                &payload.subject,
                from_state,
                to_state,
                &intent.id,
                &enforced,
                now,
            )
            .await?;
        }

        if let Some(spec) = &payload.custody {
            let prev = current_custodian(deps, tx, &payload.subject).await?;
            apply_custody(deps, tx, &payload.subject, &spec.to, spec.reason, now).await?;
            deps.outbox
                .append(
                    tx,
                    &format!("intent:{}", intent.id.as_ref()),
                    &DomainEvent::CustodyChanged {
                        subject: payload.subject.clone(),
                        from: prev,
                        to: spec.to.clone(),
                        reason: spec.reason,
                    },
                )
                .await?;
        }

        deps.outbox
            .append(
                tx,
                &format!("intent:{}", intent.id.as_ref()),
                &DomainEvent::OwnershipTransferred {
                    subject: payload.subject.clone(),
                    from: from_owner,
                    to: payload.to.clone(),
                    c2c: payload.c2c,
                    transfer_count: record.transfer_count,
                },
            )
            .await?;

        if intent.status == IntentStatus::Authorized {
            intent.advance(IntentStatus::PolicyChecked)?;
        }

        // ---- 不可逆步骤（最后）：账本锚定 ----
        deps.ledger
            .anchor(LedgerItem::Transfer {
                subject: payload.subject.clone(),
                from: record.from.clone(),
                to: record.to.clone(),
                c2c: record.c2c,
            })
            .await?;

        Ok(HandlerOutcome::Completed {
            result_ref: record.id,
            resource: subject_label(&payload.subject),
            policy: enforced,
            proof_id: None,
        })
    }
}

/// UpdateCustody 载荷。
///
/// ```json
/// {
///   "subject":      {"type": "batch", "id": "bt-001"},
///   "to":           "did:vg:user:logistics",
///   "reason":       "ship",
///   "lifecycle_to": "in_transit"   // 可选
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyPayload {
    /// 保管客体（批次或单品）。
    subject: SubjectRef,
    /// 新保管人（无需 DID 文档——物流个体可无档）。
    to: Did,
    /// 变更原因。
    reason: CustodyReason,
    /// 可选：伴随的生命周期迁移（如 ship → in_transit）。
    lifecycle_to: Option<LifecycleState>,
}

/// 保管更新处理器（L2）。
///
/// custody upsert（不读不写所有权，Phase1 **不上链**）；可选 lifecycle
/// 迁移的 policy 辖区 = subject **当前 owner** 的辖区（保管不换主，
/// 属地不迁），凭证 = 当前 owner 的 VC。owner 档案缺失而又要迁移状态时
/// 无法选策略 → InvalidInput。
pub struct UpdateCustodyHandler;

#[async_trait]
impl IntentHandler for UpdateCustodyHandler {
    fn action(&self) -> IntentAction {
        IntentAction::UpdateCustody
    }

    async fn handle(
        &self,
        deps: &AppDeps,
        tx: &mut PgTx,
        intent: &mut Intent,
        now: DateTime<Utc>,
    ) -> Result<HandlerOutcome, DomainError> {
        let payload: CustodyPayload = parse_payload(intent)?;

        // 授权闸门（owner **或** 现任 custodian，与 transfer 的 owner
        // 专属闸门不同）：owner 全程可管保管；custodian 只能沿链条交接
        // （检测机构 → 物流），且无法借本动作染指所有权——转移所有权
        // 走 TransferProduct 的 require_owner。
        let principal = effective_principal(intent);
        let owner = deps
            .ownership
            .get(tx, &payload.subject)
            .await?
            .ok_or_else(|| {
                DomainError::InvalidInput(format!(
                    "主体 {} 尚未建立所有权档案",
                    subject_label(&payload.subject)
                ))
            })?
            .owner;
        let prev = current_custodian(deps, tx, &payload.subject).await?;
        if principal != owner && prev.as_ref() != Some(&principal) {
            return Err(DomainError::Unauthorized(format!(
                "{principal} 无权操作 {}（owner={owner}）",
                subject_label(&payload.subject)
            )));
        }

        // 可选迁移：辖区/凭证取 subject 当前 owner
        let mut enforced = Vec::new();
        let mut transition: Option<(LifecycleState, LifecycleState)> = None;
        if let Some(to_state) = payload.lifecycle_to {
            // 事件日志为真相来源；无事件 = 建档态 Created。
            let from_state = deps
                .lifecycle
                .current_state(tx, &payload.subject)
                .await?
                .unwrap_or(LifecycleState::Created);
            let jurisdiction = jurisdiction_of(deps, tx, &owner, "当前所有者").await?;
            let category = product_category_of(deps, tx, &payload.subject).await?;
            enforced = enforce_transition_policy(
                deps,
                tx,
                &jurisdiction,
                &category,
                &owner,
                from_state,
                to_state,
                now,
            )
            .await?;
            transition = Some((from_state, to_state));
        }

        // ---- 落库段（无锚定：custody 不上链，Phase1 口径）----
        apply_custody(deps, tx, &payload.subject, &payload.to, payload.reason, now).await?;
        deps.outbox
            .append(
                tx,
                &format!("intent:{}", intent.id.as_ref()),
                &DomainEvent::CustodyChanged {
                    subject: payload.subject.clone(),
                    from: prev,
                    to: payload.to.clone(),
                    reason: payload.reason,
                },
            )
            .await?;

        if let Some((from_state, to_state)) = transition {
            record_lifecycle_transition(
                deps,
                tx,
                &payload.subject,
                from_state,
                to_state,
                &intent.id,
                &enforced,
                now,
            )
            .await?;
        }

        if intent.status == IntentStatus::Authorized {
            intent.advance(IntentStatus::PolicyChecked)?;
        }
        Ok(HandlerOutcome::Completed {
            // 保管无独立审计实体，结果引用派生 intent（幂等键形态）
            result_ref: format!("cu:{}", intent.id.as_ref()),
            resource: subject_label(&payload.subject),
            policy: enforced,
            proof_id: None,
        })
    }
}

/// 读取当前保管人（经 ownership 端口的 `get_custody` 读侧，不再直查 SQL）。
async fn current_custodian(
    deps: &AppDeps,
    tx: &mut PgTx,
    subject: &SubjectRef,
) -> Result<Option<Did>, DomainError> {
    Ok(deps
        .ownership
        .get_custody(tx, subject)
        .await?
        .map(|c| c.custodian))
}

/// 保管 upsert：读取现任 → [`CustodyState::apply_update`]（前手校验 +
/// 自转拒绝）→ 落库。首任（无档案）直接建档。
async fn apply_custody(
    deps: &AppDeps,
    tx: &mut PgTx,
    subject: &SubjectRef,
    to: &Did,
    reason: CustodyReason,
    now: DateTime<Utc>,
) -> Result<(), DomainError> {
    let update = CustodyUpdate {
        subject: subject.clone(),
        from: current_custodian(deps, tx, subject).await?,
        to: to.clone(),
        reason,
    };
    let mut custody = match update.from.as_ref() {
        Some(prev) => CustodyState::new(subject.clone(), prev.clone(), now),
        None => CustodyState::new(subject.clone(), to.clone(), now),
    };
    // 首任建档时 to == custodian，apply_update 的自转守卫会拒绝——
    // 首任直接落库，其余走事件消费（前手一致 + 自转拒绝）
    if update.from.is_some() {
        custody.apply_update(&update, now)?;
    }
    deps.ownership.update_custody(tx, &custody).await
}
