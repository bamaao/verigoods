//! Task 22 合规重算与查询服务：策略 ↔ 凭证 ↔ 召回联动。
//!
//! - [`recompute_compliance`]：写路径（revoke/issue handler 事务内调用），
//!   依当前有效策略重查必需凭证，不满足则**监管强制召回**（任意非终态
//!   → Recalled），满足且当前已召回时经 policy 显式允许的恢复边
//!   （Recalled → Available）自动恢复；
//! - [`check_compliance`] / [`get_required_credentials`]：只读查询
//!   （自有事务，不改任何状态）。
//!
//! ## 重算状态机联动规则（三分支，doc 锁定）
//!
//! 设 `missing` = 有效策略（`is_active(now)` 过滤）的 required_credentials
//! 并集 − 资源归属者当前有效 VC 的 ctype 集合，`cur` = 主体当前生命周期
//! 状态（事件日志终态，无事件 = Created）：
//!
//! 1. `missing` 非空且 `cur` 非 Recalled/终态 → **强制召回**：
//!    任意非终态 → Recalled（状态机全局监管边），事件 reason 列出缺失
//!    凭证、`policy_version = None`（召回不经 policy 批准，监管强制语义），
//!    outbox `ProductRecalled`；**`active` 位不回写改动**（可售语义属
//!    Delisted 上下架开关，召回不触碰）；
//! 2. `missing` 为空且 `cur == Recalled` → **恢复门**：仅当存在生效且
//!    `transitions` 含 `(Recalled, Available)` 边的策略，且
//!    [`PolicyEngine::check_transition`] 凭证核验通过时，才执行
//!    Recalled → Available（`active = true`、事件 `policy_version` =
//!    enforced 最后一条、outbox `ComplianceChanged{compliant:true}`）；
//!    无策略显式允许 → 保持 Recalled（合规已满足但恢复需 policy 授权，
//!    防止召回被静默撤销）；
//! 3. 其余情况（`cur` 非 Available/Recalled，或已满足且状态正常）→
//!    不做状态迁移，仅返回报告。
//!
//! 口径（Task 20 延续）：policy 辖区取**资源归属者**（VC subject 企业）
//! 的辖区；凭证持有者 = 归属者本人；类目取主体商品档案的 `category`。

use chrono::{DateTime, Utc};

use vg_domain::credential::CredentialType;
use vg_domain::events::DomainEvent;
use vg_domain::lifecycle::{self, LifecycleEvent, LifecycleState};
use vg_domain::policy::Policy;
use vg_domain::policy::PolicyEngine;
use vg_domain::shared::{Did, DomainError, IntentId, SubjectRef};

use crate::deps::{AppDeps, PgTx};
use crate::handlers::{product_category_of, subject_label};

/// 合规重算结论（写路径返回值）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceOutcome {
    /// 凭证是否满足当前有效策略的全量要求。
    pub compliant: bool,
    /// 缺失的凭证类型（策略并集 − 有效凭证）。
    pub missing: Vec<CredentialType>,
    /// 本次重算结束时主体是否处于 Recalled 状态。
    pub recalled: bool,
}

/// 只读合规报告（查询服务返回值）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceReport {
    /// 是否合规（无缺失即合规）。
    pub compliant: bool,
    /// 缺失的凭证类型列表。
    pub missing: Vec<CredentialType>,
}

/// 纯检核结论：owner / required 并集 / missing 差集。
struct Assessment {
    owner: Did,
    required: Vec<CredentialType>,
    missing: Vec<CredentialType>,
}

/// 步骤 1-4 的共享检核段（读路径与写路径复用，无任何状态写入）：
/// 归属者 → 辖区 → 类目 → 有效策略 → required 并集 − 有效凭证。
async fn assess(
    deps: &AppDeps,
    tx: &mut PgTx,
    subject: &SubjectRef,
    now: DateTime<Utc>,
) -> Result<Assessment, DomainError> {
    // 批次归属者：无所有权档案 → 凭证主体不明（输入错误，非权限错误）
    let owner = deps
        .ownership
        .get(tx, subject)
        .await?
        .ok_or_else(|| {
            DomainError::InvalidInput(format!(
                "主体 {} 尚未建立所有权档案，凭证归属主体不明",
                subject_label(subject)
            ))
        })?
        .owner;
    // 归属者辖区（无文档/无辖区 → 无法选策略，按建档不完整拒绝）
    let doc = deps
        .identity
        .find_document(tx, &owner)
        .await?
        .ok_or_else(|| {
            DomainError::InvalidInput(format!("归属者 {owner} 的 DID 文档不存在"))
        })?;
    let jurisdiction =
        doc.jurisdiction
            .clone()
            .ok_or_else(|| DomainError::InvalidInput(format!("归属者 {owner} 缺少辖区信息")))?;
    // 商品类目 = 策略 product_type 选择键
    let category = product_category_of(deps, tx, subject).await?;
    // 候选策略取全量（含未生效/已过期），is_active(now) 过滤在此收敛
    let policies = deps
        .policies
        .policies_for(tx, &jurisdiction, &category)
        .await?;
    let active: Vec<&Policy> = policies.iter().filter(|p| p.is_active(now)).collect();
    // required_credentials 并集（首见保序去重）
    let mut required: Vec<CredentialType> = Vec::new();
    for policy in &active {
        for ctype in &policy.required_credentials {
            if !required.contains(ctype) {
                required.push(*ctype);
            }
        }
    }
    // 有效凭证 ctype 集合（归属者持有的全部 VC 过滤 is_effective）
    let creds = deps.credentials.list_by_subject(tx, &owner).await?;
    let effective: Vec<CredentialType> = creds
        .iter()
        .filter(|vc| vc.is_effective(now))
        .map(|vc| vc.ctype)
        .collect();
    let missing: Vec<CredentialType> = required
        .iter()
        .copied()
        .filter(|ctype| !effective.contains(ctype))
        .collect();
    Ok(Assessment {
        owner,
        required,
        missing,
    })
}

/// 主体当前生命周期状态：事件日志终态；无任何事件时回读聚合档案的
/// state 字段（两者同源——建档不是迁移，批次档案 state 与事件日志
/// 由上层同步回写；直读档案避免"seed 批次无事件"被误判为 Created）。
async fn current_state(
    deps: &AppDeps,
    tx: &mut PgTx,
    subject: &SubjectRef,
) -> Result<LifecycleState, DomainError> {
    if let Some(state) = deps.lifecycle.current_state(tx, subject).await? {
        return Ok(state);
    }
    match subject {
        SubjectRef::Batch(id) => Ok(deps
            .commodity
            .find_batch(tx, id)
            .await?
            .ok_or(DomainError::NotFound)?
            .state),
        SubjectRef::Asset(id) => Ok(deps
            .commodity
            .find_asset(tx, id)
            .await?
            .ok_or(DomainError::NotFound)?
            .state),
    }
}

/// 追加生命周期事件并回写聚合状态（召回/恢复共用；事件 ID 派生自
/// intent + 后缀，同 intent 内两条迁移（先召回后恢复不可能同 intent，
/// 后缀仍保留以防未来扩展）不撞键）。
#[allow(clippy::too_many_arguments)]
async fn record_transition(
    deps: &AppDeps,
    tx: &mut PgTx,
    subject: &SubjectRef,
    from: LifecycleState,
    to: LifecycleState,
    event_suffix: &str,
    intent_id: &IntentId,
    reason: Option<String>,
    policy_version: Option<u64>,
    restore_active: bool,
    now: DateTime<Utc>,
) -> Result<(), DomainError> {
    lifecycle::assert_transition(from, to)?;
    let event = LifecycleEvent::new(
        format!("lce:{}:{event_suffix}", intent_id.as_ref()),
        subject.clone(),
        from,
        to,
        reason,
        intent_id.clone(),
        None,
        policy_version,
        now,
    )?;
    deps.lifecycle.append(tx, &event).await?;
    match subject {
        SubjectRef::Batch(id) => {
            // 召回不改 active（可售位属 Delisted 开关）；恢复恒置 true
            let active = if restore_active {
                true
            } else {
                deps.commodity
                    .find_batch(tx, id)
                    .await?
                    .ok_or(DomainError::NotFound)?
                    .active
            };
            deps.commodity
                .update_batch_state(tx, id, to, active)
                .await?;
        }
        SubjectRef::Asset(id) => {
            let mut asset = deps
                .commodity
                .find_asset(tx, id)
                .await?
                .ok_or(DomainError::NotFound)?;
            asset.state = to;
            deps.commodity.save_asset(tx, &asset).await?;
        }
    }
    Ok(())
}

/// 合规重算（写路径，三分支规则见模块 doc）。
///
/// 调用方（revoke/issue credential handler）在同一事务内传入 intent：
/// 生命周期事件 ID 与 outbox aggregate 均派生自该 intent（幂等）。
pub async fn recompute_compliance(
    deps: &AppDeps,
    tx: &mut PgTx,
    subject: &SubjectRef,
    intent_id: &IntentId,
    now: DateTime<Utc>,
) -> Result<ComplianceOutcome, DomainError> {
    let assessment = assess(deps, tx, subject, now).await?;
    let cur = current_state(deps, tx, subject).await?;
    let compliant = assessment.missing.is_empty();
    let aggregate = format!("intent:{}", intent_id.as_ref());

    // 分支 1：凭证缺失 → 监管强制召回（任意非终态 → Recalled）
    if !compliant
        && cur != LifecycleState::Recalled
        && !cur.is_terminal()
    {
        let reason = format!(
            "凭证缺失自动召回：{}",
            assessment
                .missing
                .iter()
                .map(CredentialType::as_str)
                .collect::<Vec<_>>()
                .join("、")
        );
        record_transition(
            deps,
            tx,
            subject,
            cur,
            LifecycleState::Recalled,
            "recall",
            intent_id,
            Some(reason.clone()),
            None, // 召回不经 policy 批准（监管强制语义）
            false,
            now,
        )
        .await?;
        deps.outbox
            .append(
                tx,
                &aggregate,
                &DomainEvent::ProductRecalled {
                    subject: subject.clone(),
                    reason: Some(reason),
                },
            )
            .await?;
        return Ok(ComplianceOutcome {
            compliant,
            missing: assessment.missing,
            recalled: true,
        });
    }

    // 分支 2：凭证齐备且当前已召回 → 恢复门（policy 显式允许才放行）
    if compliant && cur == LifecycleState::Recalled {
        // 归属者辖区/类目已在 assess 收敛；此处只需重取策略全集做恢复检核
        let owner = &assessment.owner;
        let doc = deps
            .identity
            .find_document(tx, owner)
            .await?
            .ok_or_else(|| {
                DomainError::InvalidInput(format!("归属者 {owner} 的 DID 文档不存在"))
            })?;
        let jurisdiction = doc
            .jurisdiction
            .clone()
            .ok_or_else(|| DomainError::InvalidInput(format!("归属者 {owner} 缺少辖区信息")))?;
        let category = product_category_of(deps, tx, subject).await?;
        let policies = deps
            .policies
            .policies_for(tx, &jurisdiction, &category)
            .await?;
        // 恢复门第一道：存在生效且声明 (Recalled, Available) 边的策略
        let allows_restore = policies
            .iter()
            .any(|p| p.is_active(now) && p.allows_transition(
                LifecycleState::Recalled,
                LifecycleState::Available,
            ));
        if allows_restore {
            // 恢复门第二道：引擎对该迁移的凭证核验（required_proofs 空
            // 集合按无证明要求处理；核验不过 → 保持 Recalled，不报错中断
            // ——撤销/签发主流程本身合法，恢复失败仅是联动结果）
            let creds = deps.credentials.list_by_subject(tx, owner).await?;
            if let Ok(decision) = PolicyEngine::check_transition(
                &policies,
                &creds,
                &[],
                LifecycleState::Recalled,
                LifecycleState::Available,
                now,
            ) {
                if !decision.enforced.is_empty() {
                    let policy_version = decision.enforced.last().map(|(_, v)| *v);
                    record_transition(
                        deps,
                        tx,
                        subject,
                        LifecycleState::Recalled,
                        LifecycleState::Available,
                        "restore",
                        intent_id,
                        Some("凭证补齐自动恢复".into()),
                        policy_version,
                        true,
                        now,
                    )
                    .await?;
                    deps.outbox
                        .append(
                            tx,
                            &aggregate,
                            &DomainEvent::ComplianceChanged {
                                subject: subject.clone(),
                                compliant: true,
                            },
                        )
                        .await?;
                    return Ok(ComplianceOutcome {
                        compliant: true,
                        missing: vec![],
                        recalled: false,
                    });
                }
            }
        }
        // 无策略显式允许 / 核验未过 → 保持 Recalled（§59 重算语义）
        return Ok(ComplianceOutcome {
            compliant: true,
            missing: vec![],
            recalled: true,
        });
    }

    // 分支 3：其余状态不做迁移，仅报告
    Ok(ComplianceOutcome {
        compliant,
        missing: assessment.missing,
        recalled: cur == LifecycleState::Recalled,
    })
}

/// 只读合规检查：复用检核 1-4 步，不改任何状态
/// （自有事务提交即结束，无业务写入）。
pub async fn check_compliance(
    deps: &AppDeps,
    subject: &SubjectRef,
) -> Result<ComplianceReport, DomainError> {
    let mut tx = deps
        .pool
        .begin()
        .await
        .map_err(|e| DomainError::Storage(format!("开启事务失败：{e}")))?;
    let assessment = assess(deps, &mut tx, subject, Utc::now()).await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    Ok(ComplianceReport {
        compliant: assessment.missing.is_empty(),
        missing: assessment.missing,
    })
}

/// 查询主体在当前时刻被要求持有的凭证类型并集
/// （仅 `is_active(now)` 过滤后的策略计入；未生效/已过期/停用不计入）。
pub async fn get_required_credentials(
    deps: &AppDeps,
    subject: &SubjectRef,
) -> Result<Vec<CredentialType>, DomainError> {
    let mut tx = deps
        .pool
        .begin()
        .await
        .map_err(|e| DomainError::Storage(format!("开启事务失败：{e}")))?;
    let assessment = assess(deps, &mut tx, subject, Utc::now()).await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    Ok(assessment.required)
}
