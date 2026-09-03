//! 商品建档与谱系处理器：CreateBatch / SplitBatch / MergeBatch / CreateItem。
//!
//! 共同说明：
//! - 建档（create_batch / create_item / merge 产新批）同时经
//!   `init_owner` 建立所有权档案（owner = 建档方），否则后续
//!   TransferProduct 无档可转（合约 `initializeOwner` 先例）；
//! - 拆分子批的所有权跟随**父批当前 owner**（无所有权档案时退回
//!   `batch.producer`），保证转移链不因拆分断链；
//! - 无任何账本锚定（商品建档 Phase1 不上链，锚定仅转移类动作）。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use vg_domain::events::DomainEvent;
use vg_domain::intent::{Intent, IntentAction, IntentStatus};
use vg_domain::lifecycle::LifecycleState;
use vg_domain::ownership::OwnershipState;
use vg_domain::shared::{BatchId, Did, DomainError, Hash32, ProductId, SubjectRef};

use crate::deps::{AppDeps, PgTx};
use crate::handlers::{
    enforce_transition_policy, jurisdiction_of, parse_payload, record_lifecycle_transition,
    require_owner, subject_label,
};
use crate::intent_engine::{HandlerOutcome, IntentHandler};

/// CreateBatch 载荷。
///
/// JSON Schema（`deny_unknown_fields`，未知字段拒绝）：
///
/// ```json
/// {
///   "subject":       {"type": "batch", "id": "bt-001"},   // 必填，审计资源
///   "product_id":    "pd-pork",
///   "quantity":      100,
///   "unit":          "kg",
///   "target_state":  "produced"        // 可选；缺省停 Created（建档非迁移）
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBatchPayload {
    /// 新批次引用（type 必须为 `batch`，其 id 即批次 ID）。
    subject: SubjectRef,
    /// 所属商品类型。
    product_id: ProductId,
    /// 数量（> 0，领域校验）。
    quantity: u64,
    /// 计量单位（非空）。
    unit: String,
    /// 建档后立即迁移到的目标状态（如 `"produced"`）。
    target_state: Option<LifecycleState>,
}

/// 批次建档处理器（L2）。
///
/// 管道：producer（`on_behalf_of` 优先）辖区校验 → 商品档案存在性 →
/// [`Batch::new`]（初始 Created）→ 可选 `target_state` 迁移（policy 检核
/// 凭证 = producer 持有的 VC）→ 落库 + `init_owner` + outbox。
///
/// - 无 `target_state`：停 Created，**不发**生命周期事件（建档不是迁移）；
/// - policy 辖区 = producer 的 DID 文档辖区（缺失 → InvalidInput）。
pub struct CreateBatchHandler;

#[async_trait]
impl IntentHandler for CreateBatchHandler {
    fn action(&self) -> IntentAction {
        IntentAction::CreateBatch
    }

    async fn handle(
        &self,
        deps: &AppDeps,
        tx: &mut PgTx,
        intent: &mut Intent,
        now: DateTime<Utc>,
    ) -> Result<HandlerOutcome, DomainError> {
        let payload: CreateBatchPayload = parse_payload(intent)?;
        let batch_id = match &payload.subject {
            SubjectRef::Batch(id) => id.clone(),
            SubjectRef::Asset(_) => {
                return Err(DomainError::InvalidInput(
                    "CreateBatch 的 subject 类型必须为 batch".into(),
                ));
            }
        };

        // producer 语义：Agent 代发时为被代理企业，否则为发起人自身
        let producer = intent
            .on_behalf_of
            .clone()
            .unwrap_or_else(|| intent.actor.clone());
        // 辖区在 target_state 场景才参与策略选择，但建档一致性要求
        // 生产者辖区始终可得（缺失即建档信息不完整）
        let jurisdiction = jurisdiction_of(deps, tx, &producer, "生产者").await?;

        // 商品档案存在性（category 同时是策略的 product_type 选择键）
        let product = deps
            .commodity
            .find_product(tx, &payload.product_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        // 重复建档守卫（save_batch 是 upsert，先查后写防静默覆盖）
        if deps.commodity.find_batch(tx, &batch_id).await?.is_some() {
            return Err(DomainError::AlreadyExists);
        }

        let mut batch = vg_domain::commodity::Batch::new(
            batch_id.clone(),
            payload.product_id.clone(),
            payload.quantity,
            payload.unit.clone(),
            now,
            producer.clone(),
        )?;

        // 可选迁移：policy 检核（凭证 = producer 的 VC）→ 状态机 → 事件
        let mut enforced = Vec::new();
        if let Some(target) = payload.target_state {
            let from = batch.state;
            enforced = enforce_transition_policy(
                deps,
                tx,
                &jurisdiction,
                &product.category,
                &producer,
                from,
                target,
                now,
            )
            .await?;
            batch.state = target;
        }

        // ---- 落库段（悬挂锚契约：本 handler 无锚定，全部写入可回滚）----
        deps.commodity.save_batch(tx, &batch).await?;
        deps.ownership
            .init_owner(
                tx,
                &OwnershipState::initialize(payload.subject.clone(), producer.clone(), now),
            )
            .await?;
        if let Some(target) = payload.target_state {
            let from = vg_domain::lifecycle::LifecycleState::Created;
            record_lifecycle_transition(
                deps,
                tx,
                &payload.subject,
                from,
                target,
                &intent.id,
                &enforced,
                now,
            )
            .await?;
        }

        deps.outbox
            .append(
                tx,
                &format!("intent:{}", intent.id.as_ref()),
                &DomainEvent::BatchCreated {
                    batch: batch_id.clone(),
                    product: payload.product_id.clone(),
                    quantity: payload.quantity,
                    producer,
                },
            )
            .await?;

        if intent.status == IntentStatus::Authorized {
            intent.advance(IntentStatus::PolicyChecked)?;
        }
        Ok(HandlerOutcome::Completed {
            result_ref: batch_id.to_string(),
            resource: subject_label(&payload.subject),
            policy: enforced,
            proof_id: None,
        })
    }
}

/// SplitBatch 载荷。
///
/// ```json
/// {
///   "subject":  {"type": "batch", "id": "bt-parent"},
///   "children": [{"id": "bt-c1", "quantity": 60}, {"id": "bt-c2", "quantity": 40}]
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SplitBatchPayload {
    /// 被拆分的父批次（type 必须为 `batch`）。
    subject: SubjectRef,
    /// 子批规格（数量守恒由领域 `Batch::split` 裁决）。
    children: Vec<ChildSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildSpec {
    /// 子批 ID。
    id: BatchId,
    /// 子批数量（> 0）。
    quantity: u64,
}

/// 批次拆分处理器（L2）。
///
/// 领域 `Batch::split` 承担全部守恒/失效守卫（子批和 = 父批量、
/// 非法即 [`DomainError::QuantityMismatch`] 等）；成功后父批失效、
/// 子批建档并继承谱系。**拆分不改变生命周期状态（子批重置 Created），
/// 不触发 policy 检核**——合规由建档迁移与后续业务迁移承担。
pub struct SplitBatchHandler;

#[async_trait]
impl IntentHandler for SplitBatchHandler {
    fn action(&self) -> IntentAction {
        IntentAction::SplitBatch
    }

    async fn handle(
        &self,
        deps: &AppDeps,
        tx: &mut PgTx,
        intent: &mut Intent,
        now: DateTime<Utc>,
    ) -> Result<HandlerOutcome, DomainError> {
        let payload: SplitBatchPayload = parse_payload(intent)?;
        let parent_id = match &payload.subject {
            SubjectRef::Batch(id) => id.clone(),
            SubjectRef::Asset(_) => {
                return Err(DomainError::InvalidInput(
                    "SplitBatch 的 subject 类型必须为 batch".into(),
                ));
            }
        };

        let mut parent = deps
            .commodity
            .find_batch(tx, &parent_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        let children: Vec<(BatchId, u64)> = payload
            .children
            .iter()
            .map(|c| (c.id.clone(), c.quantity))
            .collect();
        let outcome = parent.split(&children, now)?;

        // 授权闸门：拆分是所有权处分行为——effective principal 必须是
        // 父批当前 owner；子批所有权随之继承（不再退回 producer：无档案
        // 即异常数据，拒绝拆分）。
        let child_owner = require_owner(deps, tx, intent, &payload.subject).await?;

        // ---- 落库段 ----
        deps.commodity.save_batch(tx, &parent).await?;
        for child in &outcome.children {
            deps.commodity.save_batch(tx, child).await?;
            deps.ownership
                .init_owner(
                    tx,
                    &OwnershipState::initialize(
                        SubjectRef::Batch(child.id.clone()),
                        child_owner.clone(),
                        now,
                    ),
                )
                .await?;
        }
        deps.commodity.save_lineage(tx, &outcome.edges).await?;
        deps.outbox
            .append(
                tx,
                &format!("intent:{}", intent.id.as_ref()),
                &DomainEvent::BatchSplit {
                    parent: parent_id.clone(),
                    children: outcome.children.iter().map(|c| c.id.clone()).collect(),
                },
            )
            .await?;

        if intent.status == IntentStatus::Authorized {
            intent.advance(IntentStatus::PolicyChecked)?;
        }
        Ok(HandlerOutcome::Completed {
            result_ref: parent_id.to_string(),
            resource: subject_label(&payload.subject),
            policy: Vec::new(),
            proof_id: None,
        })
    }
}

/// MergeBatch 载荷。
///
/// ```json
/// {
///   "subject":      {"type": "batch", "id": "bt-new"},
///   "children":     ["bt-a", "bt-b"],
///   "new_batch_id": "bt-new"
/// }
/// ```
///
/// `subject` 仅为审计资源兜底保留（须指向新批），业务以 `new_batch_id` 为准。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MergeBatchPayload {
    /// 审计资源（指向合并产物）。
    subject: SubjectRef,
    /// 参与合并的父批 ID 列表。
    children: Vec<BatchId>,
    /// 合并产物的新批 ID。
    new_batch_id: BatchId,
}

/// 批次合并处理器（L2）。
///
/// 领域 `Batch::merge` 承担同源/有效/守恒裁决；新批 `producer` 取首父批
/// producer（merge 已校验全部父批 producer 一致）。与拆分同理：**不改变
/// 生命周期状态、不触发 policy**。新批所有权跟随父批 owner——授权闸门
/// 对**每个父批**逐一校验 effective principal == owner，任一父批属他人
/// 即 Unauthorized（防借合并吞噬他人所有权）。
pub struct MergeBatchHandler;

#[async_trait]
impl IntentHandler for MergeBatchHandler {
    fn action(&self) -> IntentAction {
        IntentAction::MergeBatch
    }

    async fn handle(
        &self,
        deps: &AppDeps,
        tx: &mut PgTx,
        intent: &mut Intent,
        now: DateTime<Utc>,
    ) -> Result<HandlerOutcome, DomainError> {
        let payload: MergeBatchPayload = parse_payload(intent)?;
        if let SubjectRef::Asset(_) = payload.subject {
            return Err(DomainError::InvalidInput(
                "MergeBatch 的 subject 类型必须为 batch".into(),
            ));
        }
        if payload.children.is_empty() {
            return Err(DomainError::InvalidInput("合并至少需要一个父批次".into()));
        }
        // M2：subject 是审计资源兜底，必须与业务产物 new_batch_id 一致
        if payload.subject != SubjectRef::Batch(payload.new_batch_id.clone()) {
            return Err(DomainError::InvalidInput(
                "MergeBatch 的 subject 必须指向合并产物（subject.id == new_batch_id）".into(),
            ));
        }

        let mut parents = Vec::with_capacity(payload.children.len());
        let mut new_owner: Option<Did> = None;
        for id in &payload.children {
            parents.push(
                deps.commodity
                    .find_batch(tx, id)
                    .await?
                    .ok_or(DomainError::NotFound)?,
            );
            // 授权闸门（对每个父批）：合并会吞噬父批所有权——任一父批
            // 不属于 effective principal 即整体拒绝，不得借合并吞他人批次。
            let owner = require_owner(deps, tx, intent, &SubjectRef::Batch(id.clone())).await?;
            if new_owner.is_none() {
                new_owner = Some(owner);
            }
        }
        // 每个父批都通过了 owner == principal 闸门 → 所有父批同主
        let new_owner = new_owner.expect("children 非空则 new_owner 必有值");
        let producer = parents[0].producer.clone();

        let outcome = vg_domain::commodity::Batch::merge(
            &mut parents,
            payload.new_batch_id.clone(),
            producer,
            now,
        )?;

        // ---- 落库段 ----
        for parent in &parents {
            deps.commodity.save_batch(tx, parent).await?;
        }
        deps.commodity.save_batch(tx, &outcome.batch).await?;
        deps.ownership
            .init_owner(
                tx,
                &OwnershipState::initialize(
                    SubjectRef::Batch(payload.new_batch_id.clone()),
                    new_owner,
                    now,
                ),
            )
            .await?;
        deps.commodity.save_lineage(tx, &outcome.edges).await?;
        deps.outbox
            .append(
                tx,
                &format!("intent:{}", intent.id.as_ref()),
                &DomainEvent::BatchMerged {
                    children: payload.children.clone(),
                    new_batch: payload.new_batch_id.clone(),
                },
            )
            .await?;

        if intent.status == IntentStatus::Authorized {
            intent.advance(IntentStatus::PolicyChecked)?;
        }
        Ok(HandlerOutcome::Completed {
            result_ref: payload.new_batch_id.to_string(),
            resource: subject_label(&payload.subject),
            policy: Vec::new(),
            proof_id: None,
        })
    }
}

/// CreateItem 载荷。
///
/// ```json
/// {
///   "subject":                 {"type": "asset", "id": "as-001"},
///   "product_id":              "pd-luxury-bag",
///   "authenticity_commitment": "0x…",   // 32 字节 hex，不得为零哈希
///   "manufacturer":            "did:vg:user:maker"   // 可选，缺省为被代理方/发起人
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateItemPayload {
    /// 新单品引用（type 必须为 `asset`）。
    subject: SubjectRef,
    /// 所属商品类型。
    product_id: ProductId,
    /// 防伪承诺（合约 zero hash 校验同款，领域拒绝零哈希）。
    authenticity_commitment: Hash32,
    /// 制造商；缺省 = `on_behalf_of`（Agent 代发）或发起人。
    manufacturer: Option<Did>,
}

/// 单品建档处理器（L2）。
///
/// manufacturer 三级缺省：payload 显式指定 → `on_behalf_of` → actor。
/// 建档不迁移状态（初始 Created、无生命周期事件、无 policy），
/// 同时 `init_owner`（owner = manufacturer）+ outbox。
pub struct CreateItemHandler;

#[async_trait]
impl IntentHandler for CreateItemHandler {
    fn action(&self) -> IntentAction {
        IntentAction::CreateItem
    }

    async fn handle(
        &self,
        deps: &AppDeps,
        tx: &mut PgTx,
        intent: &mut Intent,
        now: DateTime<Utc>,
    ) -> Result<HandlerOutcome, DomainError> {
        let payload: CreateItemPayload = parse_payload(intent)?;
        let asset_id = match &payload.subject {
            SubjectRef::Asset(id) => id.clone(),
            SubjectRef::Batch(_) => {
                return Err(DomainError::InvalidInput(
                    "CreateItem 的 subject 类型必须为 asset".into(),
                ));
            }
        };

        let manufacturer = payload
            .manufacturer
            .clone()
            .or_else(|| intent.on_behalf_of.clone())
            .unwrap_or_else(|| intent.actor.clone());

        // 建档一致性：制造商 DID 可解析（与批次建档同一口径，不强制辖区）
        if deps
            .identity
            .find_document(tx, &manufacturer)
            .await?
            .is_none()
        {
            return Err(DomainError::Unauthorized(format!(
                "制造商 DID 文档不存在：{manufacturer}"
            )));
        }
        // 商品档案存在性（建档引用必须有效）
        if deps
            .commodity
            .find_product(tx, &payload.product_id)
            .await?
            .is_none()
        {
            return Err(DomainError::NotFound);
        }
        if deps.commodity.find_asset(tx, &asset_id).await?.is_some() {
            return Err(DomainError::AlreadyExists);
        }

        let asset = vg_domain::commodity::Asset::new(
            asset_id.clone(),
            payload.product_id.clone(),
            manufacturer.clone(),
            payload.authenticity_commitment,
            now,
        )?;

        // ---- 落库段 ----
        deps.commodity.save_asset(tx, &asset).await?;
        deps.ownership
            .init_owner(
                tx,
                &OwnershipState::initialize(payload.subject.clone(), manufacturer.clone(), now),
            )
            .await?;
        deps.outbox
            .append(
                tx,
                &format!("intent:{}", intent.id.as_ref()),
                &DomainEvent::AssetCreated {
                    asset: asset_id.clone(),
                    product: payload.product_id.clone(),
                    manufacturer,
                },
            )
            .await?;

        if intent.status == IntentStatus::Authorized {
            intent.advance(IntentStatus::PolicyChecked)?;
        }
        Ok(HandlerOutcome::Completed {
            result_ref: asset_id.to_string(),
            resource: subject_label(&payload.subject),
            policy: Vec::new(),
            proof_id: None,
        })
    }
}
