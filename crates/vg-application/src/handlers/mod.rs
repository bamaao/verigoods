//! Task 20 业务段处理器：商品（批次/单品/谱系）与公开转移/保管用例。
//!
//! 模块结构：
//! - [`commodity`]：CreateBatch / SplitBatch / MergeBatch / CreateItem；
//! - [`transfer`]：TransferProduct（公开转移）/ UpdateCustody（保管更新）。
//!
//! 共同契约（各 handler doc 详述 payload JSON Schema）：
//! - payload 反序列化为强类型 struct（`deny_unknown_fields` 拒绝未知字段），
//!   **必须含 `subject` 字段**（[`SubjectRef`] 对象形）——engine 拒绝路径
//!   的审计资源兜底（见 `intent_engine::deny_resource`）；
//! - 生命周期迁移一律走「policy 检核 → `assert_transition` → 事件追加 →
//!   聚合状态回写」四步，策略辖区口径见 [`jurisdiction_of`]；
//! - `ledger.anchor` 是 handler 内**最后一个不可逆步骤**（悬挂锚契约，
//!   见 [`IntentHandler`](crate::intent_engine::IntentHandler)）——本任务
//!   仅 TransferProduct 锚定，custody 不上链（Phase1 口径）。

pub mod commodity;
pub mod transfer;

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;

use vg_domain::lifecycle::LifecycleState;
use vg_domain::policy::{PolicyEngine, PolicyVersion};
use vg_domain::shared::{Did, DomainError, SubjectRef};

use crate::deps::{AppDeps, PgTx};
use crate::intent_engine::HandlerMap;

/// 注册 Task 20 的默认处理器集合（6 个动作）。
///
/// bootstrap（Task 23）经此一键装配；同动作后注册覆盖先注册。
pub fn register_default(map: &mut HandlerMap) {
    map.register(Arc::new(commodity::CreateBatchHandler));
    map.register(Arc::new(commodity::SplitBatchHandler));
    map.register(Arc::new(commodity::MergeBatchHandler));
    map.register(Arc::new(commodity::CreateItemHandler));
    map.register(Arc::new(transfer::TransferPublicHandler));
    map.register(Arc::new(transfer::UpdateCustodyHandler));
}

/// subject 的审计/资源编码（与 infra `encode_subject` 同一口径）：
/// `batch:bt-1` / `asset:a-1`。
pub(crate) fn subject_label(subject: &SubjectRef) -> String {
    match subject {
        SubjectRef::Batch(id) => format!("batch:{id}"),
        SubjectRef::Asset(id) => format!("asset:{id}"),
    }
}

/// payload → 强类型（`deny_unknown_fields` 由各 struct 自带）。
///
/// 违规 → [`DomainError::InvalidInput`]（业务拒绝而非调用方 Err：
/// 意图已落库，拒绝留痕走审计）。
pub(crate) fn parse_payload<T: DeserializeOwned>(intent: &vg_domain::intent::Intent) -> Result<T, DomainError> {
    serde_json::from_value(intent.payload.clone()).map_err(|e| {
        DomainError::InvalidInput(format!("payload 不符合契约：{e}"))
    })
}

/// 读取 DID 文档的辖区；文档缺失 → [`DomainError::Unauthorized`]，
/// 辖区为 `None` → [`DomainError::InvalidInput`]。
///
/// **policy 辖区口径（doc 锁定）**：
/// - CreateBatch / CreateItem：建档方（producer / manufacturer）的辖区；
/// - TransferProduct：**转移前 owner** 的辖区（商品合规跟随出让方属地）；
/// - UpdateCustody：subject 当前 owner 的辖区（保管不换主，属地不迁）。
///
/// 辖区缺失即无法选策略——视为建档不完整的输入错误，而非放行。
pub(crate) async fn jurisdiction_of(
    deps: &AppDeps,
    tx: &mut PgTx,
    did: &Did,
    role: &str,
) -> Result<String, DomainError> {
    let doc = deps
        .identity
        .find_document(tx, did)
        .await?
        .ok_or_else(|| DomainError::Unauthorized(format!("{role}的 DID 文档不存在：{did}")))?;
    doc.jurisdiction
        .clone()
        .ok_or_else(|| DomainError::InvalidInput(format!("{role}缺少辖区信息：{did}")))
}

/// subject 所属商品类目（policy 的 `product_type` 选择键）。
///
/// 按主体形态读批次/单品档案，再取商品类型的 `category`；
/// 任一档案缺失 → [`DomainError::NotFound`]。
pub(crate) async fn product_category_of(
    deps: &AppDeps,
    tx: &mut PgTx,
    subject: &SubjectRef,
) -> Result<String, DomainError> {
    let product_id = match subject {
        SubjectRef::Batch(id) => {
            deps.commodity
                .find_batch(tx, id)
                .await?
                .ok_or(DomainError::NotFound)?
                .product
        }
        SubjectRef::Asset(id) => deps
            .commodity
            .find_asset(tx, id)
            .await?
            .ok_or(DomainError::NotFound)?
            .product,
    };
    Ok(deps
        .commodity
        .find_product(tx, &product_id)
        .await?
        .ok_or(DomainError::NotFound)?
        .category)
}

/// 生命周期迁移的策略检核（Task 20 统一入口）。
///
/// `cred_subject` 为**凭证持有者**（资源归属者：producer / 转移前 owner），
/// required_credentials 按该主体的 VC 集合匹配；证明集合本任务恒空
/// （ZK 证明由 Task 21/22 注入）。
///
/// 状态机合法性（`assert_transition`）由调用方在检核通过后自行裁决——
/// 策略放行不等于状态机合法，两道闸门独立。
#[allow(clippy::too_many_arguments)] // 检核要素即策略引擎全签名，聚合成结构体会掩盖缺省语义
pub(crate) async fn enforce_transition_policy(
    deps: &AppDeps,
    tx: &mut PgTx,
    jurisdiction: &str,
    product_type: &str,
    cred_subject: &Did,
    from: LifecycleState,
    to: LifecycleState,
    now: DateTime<Utc>,
) -> Result<Vec<PolicyVersion>, DomainError> {
    let policies = deps
        .policies
        .policies_for(tx, jurisdiction, product_type)
        .await?;
    let creds = deps
        .credentials
        .list_by_subject(tx, cred_subject)
        .await?;
    let decision = PolicyEngine::check_transition(&policies, &creds, &[], from, to, now)?;
    Ok(decision.enforced)
}

/// 生命周期迁移落库四件套（policy 检核后的公共后段）：
/// `assert_transition` → lifecycle 事件追加（事件 ID 派生自 intent，幂等）
/// → 批次/单品聚合状态回写（`active` 不变——迁移不失效档案）。
///
/// `policy_version` 取 enforced 最后一条（与 engine 审计列同口径）。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn record_lifecycle_transition(
    deps: &AppDeps,
    tx: &mut PgTx,
    subject: &SubjectRef,
    from: LifecycleState,
    to: LifecycleState,
    intent_id: &vg_domain::shared::IntentId,
    policy: &[PolicyVersion],
    now: DateTime<Utc>,
) -> Result<(), DomainError> {
    vg_domain::lifecycle::assert_transition(from, to)?;
    let event = vg_domain::lifecycle::LifecycleEvent::new(
        // 事件 ID 派生自 intent：审批续跑/重放路径下同 id 幂等去重
        format!("lce:{}", intent_id.as_ref()),
        subject.clone(),
        from,
        to,
        None,
        intent_id.clone(),
        None,
        policy.last().map(|(_, v)| *v),
        now,
    )?;
    deps.lifecycle.append(tx, &event).await?;
    match subject {
        SubjectRef::Batch(id) => {
            deps.commodity.update_batch_state(tx, id, to, true).await?;
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

#[cfg(test)]
mod tests {
    //! Task 20 e2e-ish 测试（sqlx::test，与 intent_engine 同风格）。
    //!
    //! 五步猪肉管道：生产（create_batch + ProductionLicense policy）
    //! → 检测（UpdateCustody handover + QualityInspection policy）
    //! → 转运（ship + Inspected→InTransit）→ 零售（transfer_public
    //! InTransit→Available + warehouse_in）→ 消费者（transfer c2c
    //! Available→Sold）；另覆盖守恒拆分后子批独立转移、合并、单品建档
    //! 与拒绝路径（数量不守恒 / 自转 / 未建档 / 缺凭证 PolicyViolated）。

    use super::*;
    use async_trait::async_trait;
    use vg_domain::commodity::ports::CommodityRepository;
    use vg_domain::credential::ports::CredentialRepository;
    use vg_domain::credential::{CredentialType, VerifiableCredential};
    use vg_domain::identity::ports::IdentityRepository;
    use vg_domain::identity::{
        Capability, DidDocument, KeyType, SubjectKind, VerificationMethod,
    };
    use vg_domain::intent::{IntentAction, IntentStatus, RiskLevel};
    use vg_domain::policy::ports::PolicyRepository;
    use vg_domain::policy::Policy;
    use vg_domain::ports::{CircuitSpec, NoteHasher, ProofProver, Witness};
    use vg_domain::shared::{
        CredentialId, DomainError, Hash32, IntentId, PolicyId, ProductId,
    };
    use vg_infra_pg::{
        InProcessLedger, PgApprovalsStore, PgAuditWriter, PgCommodityRepo, PgCredentialRepo,
        PgIdentityRepo, PgIntentRepository, PgLifecycleRepo, PgOutbox, PgOwnershipRepo,
        PgPolicyRepository, PgProofStore,
    };

    // ---- 测试桩：prover / hasher（与 intent_engine 测试同款） ----

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

    // ---- fixture ----

    fn did(s: &str) -> Did {
        Did::parse(s).unwrap()
    }

    fn doc(
        did: Did,
        kind: SubjectKind,
        parent: Option<Did>,
        jurisdiction: Option<String>,
    ) -> DidDocument {
        DidDocument {
            did: did.clone(),
            kind,
            methods: vec![VerificationMethod::new(
                "k-0",
                KeyType::Secp256k1,
                Hash32::keccak(b"pk"),
                did,
            )],
            parent,
            jurisdiction,
            created_at: Utc::now(),
        }
    }

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

    fn engine(pool: sqlx::PgPool) -> crate::intent_engine::IntentEngine {
        let mut map = HandlerMap::new();
        register_default(&mut map);
        crate::intent_engine::IntentEngine::new(deps(pool), map)
    }

    /// 建企业主体（辖区 CN）+ 能力授予；grantor 一并建档。
    async fn seed_enterprise(
        pool: &sqlx::PgPool,
        enterprise: &Did,
        caps: &[vg_domain::identity::capability::Action],
    ) {
        let mut tx = pool.begin().await.unwrap();
        let identity = PgIdentityRepo;
        identity
            .save_document(
                &mut tx,
                &doc(
                    enterprise.clone(),
                    SubjectKind::Enterprise,
                    None,
                    Some("CN".into()),
                ),
            )
            .await
            .unwrap();
        let grantor = did("did:vg:user:grantor-t20");
        identity
            .save_document(
                &mut tx,
                &doc(grantor.clone(), SubjectKind::Enterprise, None, Some("CN".into())),
            )
            .await
            .unwrap();
        for cap in caps {
            identity
                .grant_capability(
                    &mut tx,
                    &Capability::new(enterprise.clone(), *cap, grantor.clone(), None).unwrap(),
                )
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
    }

    /// 商品档案（类目 food = 策略 product_type 匹配键）。
    async fn seed_product(pool: &sqlx::PgPool, id: &str) {
        let mut tx = pool.begin().await.unwrap();
        PgCommodityRepo
            .save_product(
                &mut tx,
                &vg_domain::commodity::ProductType::new(
                    ProductId::new(id),
                    "food",
                    Hash32::keccak(b"pork-meta"),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    /// 策略行：CN × food，Created→Produced 需 production_license（v1）；
    /// Produced→Inspected 需 quality_inspection（v3）。
    async fn seed_policies(pool: &sqlx::PgPool) {
        let authority = did("did:vg:user:reg-cn");
        let mk = |id: &str,
                  version: u64,
                  cred: CredentialType,
                  from: LifecycleState,
                  to: LifecycleState| Policy {
            policy_id: PolicyId::new(id),
            version,
            authority: authority.clone(),
            jurisdiction: "CN".into(),
            product_type: "food".into(),
            required_credentials: vec![cred],
            required_proofs: vec![],
            transitions: vec![(from, to)],
            effective_at: Utc::now() - chrono::Duration::days(1),
            expires_at: None,
            active: true,
        };
        let mut tx = pool.begin().await.unwrap();
        PgPolicyRepository
            .save_policy(
                &mut tx,
                &mk(
                    "pol-prod",
                    1,
                    CredentialType::ProductionLicense,
                    LifecycleState::Created,
                    LifecycleState::Produced,
                ),
            )
            .await
            .unwrap();
        PgPolicyRepository
            .save_policy(
                &mut tx,
                &mk(
                    "pol-insp",
                    3,
                    CredentialType::QualityInspection,
                    LifecycleState::Produced,
                    LifecycleState::Inspected,
                ),
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    /// 给企业签发 VC（subject=企业——资源归属者持有凭证）。
    async fn seed_vc(pool: &sqlx::PgPool, ctype: CredentialType, subject: &Did) {
        let issuer = did("did:vg:user:issuer-t20");
        let mut tx = pool.begin().await.unwrap();
        PgCredentialRepo
            .save(
                &mut tx,
                &VerifiableCredential::new(
                    CredentialId::generate(),
                    issuer,
                    subject.clone(),
                    ctype,
                    serde_json::json!({"scope": "fixture"}),
                    Utc::now() - chrono::Duration::days(1),
                    Some(Utc::now() + chrono::Duration::days(365)),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    fn raw(
        id: &str,
        action: IntentAction,
        actor: &Did,
        payload: serde_json::Value,
    ) -> crate::intent_engine::RawIntent {
        use std::sync::atomic::{AtomicU64, Ordering};
        // nonce 单调递增：同测试内多条 intent 不得撞 (actor, nonce) 防重放键
        static NONCE: AtomicU64 = AtomicU64::new(1);
        crate::intent_engine::RawIntent {
            id: IntentId::new(id),
            action,
            actor: actor.clone(),
            on_behalf_of: None,
            payload,
            nonce: NONCE.fetch_add(1, Ordering::SeqCst),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }
    }

    fn batch_subject(id: &str) -> serde_json::Value {
        serde_json::json!({"type": "batch", "id": id})
    }

    // ---- SQL 断言小件 ----

    async fn ownership_row(pool: &sqlx::PgPool, subject: &str) -> (String, i64, i64) {
        let row: (String, i64, i64) = sqlx::query_as(
            "SELECT owner, transfer_count, c2c_count FROM ownership_states WHERE subject = $1",
        )
        .bind(subject)
        .fetch_one(pool)
        .await
        .unwrap();
        row
    }

    async fn batch_active_state(pool: &sqlx::PgPool, id: &str) -> (bool, String) {
        let row: (bool, String) = sqlx::query_as("SELECT active, state FROM batches WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
        row
    }

    async fn lifecycle_chain(
        pool: &sqlx::PgPool,
        subject: &str,
    ) -> Vec<(String, String, Option<i64>)> {
        sqlx::query_as(
            "SELECT from_state, to_state, policy_version FROM lifecycle_events \
             WHERE subject = $1 ORDER BY at ASC, id ASC",
        )
        .bind(subject)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    async fn outbox_types(pool: &sqlx::PgPool, intent_id: &str) -> Vec<String> {
        let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
            "SELECT payload FROM domain_events WHERE aggregate = $1 ORDER BY id ASC",
        )
        .bind(format!("intent:{intent_id}"))
        .fetch_all(pool)
        .await
        .unwrap();
        rows.into_iter()
            .map(|(p,)| p["event_type"].as_str().unwrap().to_string())
            .collect()
    }

    async fn audit_policy(pool: &sqlx::PgPool, intent_id: &str) -> (Option<String>, Option<i64>) {
        let row: (Option<String>, Option<i64>) = sqlx::query_as(
            "SELECT policy_id, policy_version FROM audit_events \
             WHERE intent_id = $1 AND result = 'allow'",
        )
        .bind(intent_id)
        .fetch_one(pool)
        .await
        .unwrap();
        row
    }

    /// 五步猪肉管道（plan 必测）。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn pork_pipeline_five_steps_full_green(pool: sqlx::PgPool) {
        let enterprise = did("did:vg:user:ent-farm");
        let inspector = did("did:vg:user:inspector");
        let logistics = did("did:vg:user:logistics");
        let retailer = did("did:vg:user:retailer");
        let consumer = did("did:vg:user:consumer");

        use vg_domain::identity::capability::Action as Cap;
        seed_enterprise(
            &pool,
            &enterprise,
            &[Cap::CreateBatch, Cap::TransferOwnership, Cap::UpdateCustody],
        )
        .await;
        // 转移执行方（零售商）也需要 TransferOwnership 能力与 DID 文档
        {
            let mut tx = pool.begin().await.unwrap();
            PgIdentityRepo
                .save_document(
                    &mut tx,
                    &doc(retailer.clone(), SubjectKind::Enterprise, None, Some("CN".into())),
                )
                .await
                .unwrap();
            let grantor = did("did:vg:user:grantor-t20");
            PgIdentityRepo
                .grant_capability(
                    &mut tx,
                    &Capability::new(retailer.clone(), Cap::TransferOwnership, grantor, None)
                        .unwrap(),
                )
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        seed_product(&pool, "pd-pork").await;
        seed_policies(&pool).await;
        seed_vc(&pool, CredentialType::ProductionLicense, &enterprise).await;
        seed_vc(&pool, CredentialType::QualityInspection, &enterprise).await;

        let eng = engine(pool.clone());
        let subject = batch_subject("bt-pork");
        let label = "batch:bt-pork";

        // 步骤 1：建档 + Created→Produced（ProductionLicense policy 命中）
        let r1 = eng
            .execute(raw(
                "p-1",
                IntentAction::CreateBatch,
                &enterprise,
                serde_json::json!({
                    "subject": subject, "product_id": "pd-pork",
                    "quantity": 100, "unit": "kg", "target_state": "produced"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(r1.status, IntentStatus::Confirmed);
        assert_eq!(r1.result_ref.as_deref(), Some("bt-pork"));
        assert_eq!(
            audit_policy(&pool, "p-1").await,
            (Some("pol-prod".into()), Some(1))
        );
        assert_eq!(
            batch_active_state(&pool, "bt-pork").await,
            (true, "produced".into())
        );
        assert_eq!(
            lifecycle_chain(&pool, label).await,
            vec![("created".into(), "produced".into(), Some(1))]
        );
        assert_eq!(outbox_types(&pool, "p-1").await, vec!["batch_created"]);
        // 建档即建所有权：owner = 生产者、零计数
        assert_eq!(
            ownership_row(&pool, label).await,
            (enterprise.to_string(), 0, 0)
        );

        // 步骤 2：检测——custody handover 给检测机构 + Produced→Inspected
        let r2 = eng
            .execute(raw(
                "p-2",
                IntentAction::UpdateCustody,
                &enterprise,
                serde_json::json!({
                    "subject": subject, "to": inspector.to_string(),
                    "reason": "handover", "lifecycle_to": "inspected"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(r2.status, IntentStatus::Confirmed);
        assert_eq!(
            audit_policy(&pool, "p-2").await,
            (Some("pol-insp".into()), Some(3))
        );
        assert_eq!(
            batch_active_state(&pool, "bt-pork").await,
            (true, "inspected".into())
        );
        assert_eq!(outbox_types(&pool, "p-2").await, vec!["custody_changed"]);
        let custodian: (String,) =
            sqlx::query_as("SELECT custodian FROM custody_states WHERE subject = $1")
                .bind(label)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(custodian.0, inspector.to_string());

        // 步骤 3：转运——custody ship 给物流 + Inspected→InTransit（无策略约束）
        let r3 = eng
            .execute(raw(
                "p-3",
                IntentAction::UpdateCustody,
                &enterprise,
                serde_json::json!({
                    "subject": subject, "to": logistics.to_string(),
                    "reason": "ship", "lifecycle_to": "in_transit"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(r3.status, IntentStatus::Confirmed);
        assert_eq!(
            audit_policy(&pool, "p-3").await,
            (None, None),
            "无适用策略 → 审计 policy 列为空"
        );
        assert_eq!(
            batch_active_state(&pool, "bt-pork").await,
            (true, "in_transit".into())
        );

        // 步骤 4：企业→零售商（InTransit→Available + custody warehouse_in）
        let r4 = eng
            .execute(raw(
                "p-4",
                IntentAction::TransferProduct,
                &enterprise,
                serde_json::json!({
                    "subject": subject, "to": retailer.to_string(), "c2c": false,
                    "lifecycle_to": "available",
                    "custody": {"to": retailer.to_string(), "reason": "warehouse_in"}
                }),
            ))
            .await
            .unwrap();
        assert_eq!(r4.status, IntentStatus::Confirmed);
        assert_eq!(r4.risk, RiskLevel::L3);
        assert_eq!(r4.result_ref.as_deref(), Some("tr:p-4"), "转移记录 ID 派生自 intent");
        assert_eq!(
            ownership_row(&pool, label).await,
            (retailer.to_string(), 1, 0)
        );
        assert_eq!(
            batch_active_state(&pool, "bt-pork").await,
            (true, "available".into())
        );
        let mut evs = outbox_types(&pool, "p-4").await;
        evs.sort();
        assert_eq!(evs, vec!["custody_changed", "ownership_transferred"]);
        // 账本锚定：transfer 分录一条
        let anchored: (i64,) =
            sqlx::query_as("SELECT count(*) FROM ledger_anchors WHERE kind = 'transfer'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(anchored.0, 1);

        // 步骤 5：零售商→消费者（c2c=true，Available→Sold）
        let r5 = eng
            .execute(raw(
                "p-5",
                IntentAction::TransferProduct,
                &retailer,
                serde_json::json!({
                    "subject": subject, "to": consumer.to_string(),
                    "c2c": true, "lifecycle_to": "sold"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(r5.status, IntentStatus::Confirmed);
        assert_eq!(
            ownership_row(&pool, label).await,
            (consumer.to_string(), 2, 1)
        );
        assert_eq!(
            batch_active_state(&pool, "bt-pork").await,
            (true, "sold".into())
        );

        // 全链断言：owner 链（transfers 流水两笔、计数连续）
        let transfers: Vec<(String, String, bool, i64, i64)> = sqlx::query_as(
            "SELECT from_did, to_did, c2c, transfer_count, c2c_count FROM transfers \
             WHERE subject = $1 ORDER BY serial ASC",
        )
        .bind(label)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(transfers.len(), 2);
        assert_eq!(transfers[0].1, retailer.to_string());
        assert_eq!((transfers[0].3, transfers[0].4), (1, 0));
        assert_eq!(transfers[1].1, consumer.to_string());
        assert_eq!((transfers[1].3, transfers[1].4), (2, 1));

        // 生命周期事件序与 policy_version（前两步有策略版本，后三步无）
        assert_eq!(
            lifecycle_chain(&pool, label).await,
            vec![
                ("created".into(), "produced".into(), Some(1)),
                ("produced".into(), "inspected".into(), Some(3)),
                ("inspected".into(), "in_transit".into(), None),
                ("in_transit".into(), "available".into(), None),
                ("available".into(), "sold".into(), None),
            ]
        );

        // 幂等重放：同 intent 重提交不双计
        let replay = eng
            .execute(raw(
                "p-4",
                IntentAction::TransferProduct,
                &enterprise,
                serde_json::json!({"subject": subject}),
            ))
            .await
            .unwrap();
        assert_eq!(replay.status, IntentStatus::Confirmed);
        assert_eq!(
            ownership_row(&pool, label).await,
            (consumer.to_string(), 2, 1),
            "重放不得改变计数"
        );
        let transfers_count: (i64,) =
            sqlx::query_as("SELECT count(*) FROM transfers WHERE subject = $1")
                .bind(label)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(transfers_count.0, 2, "重放不得新增转移流水");
        let anchored: (i64,) =
            sqlx::query_as("SELECT count(*) FROM ledger_anchors WHERE kind = 'transfer'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(anchored.0, 2, "重放不得二次锚定");
    }

    /// 守恒拆分（plan 必测）：拆成两子批后各自独立转移给不同买方。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn split_children_transfer_independently(pool: sqlx::PgPool) {
        let enterprise = did("did:vg:user:ent-split");
        let buyer_a = did("did:vg:user:buyer-a");
        let buyer_b = did("did:vg:user:buyer-b");
        use vg_domain::identity::capability::Action as Cap;
        seed_enterprise(&pool, &enterprise, &[Cap::CreateBatch, Cap::TransferOwnership]).await;
        seed_product(&pool, "pd-pork").await;
        let eng = engine(pool.clone());

        // 建批（停 Created，无迁移无 policy）
        let r0 = eng
            .execute(raw(
                "s-0",
                IntentAction::CreateBatch,
                &enterprise,
                serde_json::json!({
                    "subject": batch_subject("bt-f"),
                    "product_id": "pd-pork", "quantity": 100, "unit": "kg"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(r0.status, IntentStatus::Confirmed);
        assert_eq!(
            batch_active_state(&pool, "bt-f").await,
            (true, "created".into())
        );
        // 建档非迁移：无生命周期事件
        assert!(lifecycle_chain(&pool, "batch:bt-f").await.is_empty());

        // 守恒拆分：60 + 40 = 100
        let r1 = eng
            .execute(raw(
                "s-1",
                IntentAction::SplitBatch,
                &enterprise,
                serde_json::json!({
                    "subject": batch_subject("bt-f"),
                    "children": [
                        {"id": "bt-c1", "quantity": 60},
                        {"id": "bt-c2", "quantity": 40}
                    ]
                }),
            ))
            .await
            .unwrap();
        assert_eq!(r1.status, IntentStatus::Confirmed);
        assert_eq!(outbox_types(&pool, "s-1").await, vec!["batch_split"]);
        assert_eq!(
            batch_active_state(&pool, "bt-f").await,
            (false, "created".into()),
            "父批失效"
        );
        assert_eq!(
            batch_active_state(&pool, "bt-c1").await,
            (true, "created".into())
        );
        assert_eq!(
            batch_active_state(&pool, "bt-c2").await,
            (true, "created".into())
        );
        // 谱系边 2 条（父→各子）
        let edges: (i64,) =
            sqlx::query_as("SELECT count(*) FROM batch_lineage WHERE parent = 'bt-f'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(edges.0, 2);
        // 子批数量守恒
        let qty: (i64,) = sqlx::query_as("SELECT quantity FROM batches WHERE id = 'bt-c1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(qty.0, 60);

        // 子批各自独立转移
        for (intent, child, buyer) in [("s-2", "bt-c1", &buyer_a), ("s-3", "bt-c2", &buyer_b)] {
            let r = eng
                .execute(raw(
                    intent,
                    IntentAction::TransferProduct,
                    &enterprise,
                    serde_json::json!({
                        "subject": batch_subject(child),
                        "to": buyer.to_string(), "c2c": false
                    }),
                ))
                .await
                .unwrap();
            assert_eq!(r.status, IntentStatus::Confirmed, "{child} 转移应成功");
        }
        assert_eq!(
            ownership_row(&pool, "batch:bt-c1").await,
            (buyer_a.to_string(), 1, 0),
            "子批计数独立"
        );
        assert_eq!(
            ownership_row(&pool, "batch:bt-c2").await,
            (buyer_b.to_string(), 1, 0),
            "子批计数独立"
        );
        // 父批档案保留（追溯），所有权档案不因拆分消失
        assert_eq!(
            ownership_row(&pool, "batch:bt-f").await,
            (enterprise.to_string(), 0, 0)
        );

        // 拒绝路径：数量不守恒（60+50≠100 的另一父批）
        eng.execute(raw(
            "s-x0",
            IntentAction::CreateBatch,
            &enterprise,
            serde_json::json!({
                "subject": batch_subject("bt-g"),
                "product_id": "pd-pork", "quantity": 100, "unit": "kg"
            }),
        ))
        .await
        .unwrap();
        let bad = eng
            .execute(raw(
                "s-x1",
                IntentAction::SplitBatch,
                &enterprise,
                serde_json::json!({
                    "subject": batch_subject("bt-g"),
                    "children": [
                        {"id": "bt-x1", "quantity": 60},
                        {"id": "bt-x2", "quantity": 50}
                    ]
                }),
            ))
            .await
            .unwrap();
        assert_eq!(bad.status, IntentStatus::Rejected);
        assert!(
            bad.rejection.as_deref().is_some_and(|r| r.contains("数量不一致")),
            "实际：{:?}",
            bad.rejection
        );
        // 失败零副作用：bt-g 仍有效、无子批
        assert_eq!(
            batch_active_state(&pool, "bt-g").await,
            (true, "created".into())
        );
        let kids: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM batches WHERE id IN ('bt-x1','bt-x2')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(kids.0, 0);
    }

    /// 同源两批合并回新批（谱系 + 数量守恒 + 所有权建档）。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn merge_same_origin_batches(pool: sqlx::PgPool) {
        let enterprise = did("did:vg:user:ent-merge");
        use vg_domain::identity::capability::Action as Cap;
        seed_enterprise(&pool, &enterprise, &[Cap::CreateBatch]).await;
        seed_product(&pool, "pd-pork").await;
        let eng = engine(pool.clone());

        for (id, qty) in [("bt-m1", 30u64), ("bt-m2", 20u64)] {
            eng.execute(raw(
                &format!("m-{id}"),
                IntentAction::CreateBatch,
                &enterprise,
                serde_json::json!({
                    "subject": batch_subject(id),
                    "product_id": "pd-pork", "quantity": qty, "unit": "kg"
                }),
            ))
            .await
            .unwrap();
        }

        let r = eng
            .execute(raw(
                "m-merge",
                IntentAction::MergeBatch,
                &enterprise,
                serde_json::json!({
                    "subject": batch_subject("bt-m"),
                    "children": ["bt-m1", "bt-m2"],
                    "new_batch_id": "bt-m"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(r.status, IntentStatus::Confirmed);
        assert_eq!(r.result_ref.as_deref(), Some("bt-m"));
        assert_eq!(outbox_types(&pool, "m-merge").await, vec!["batch_merged"]);
        assert_eq!(
            batch_active_state(&pool, "bt-m1").await,
            (false, "created".into())
        );
        assert_eq!(
            batch_active_state(&pool, "bt-m2").await,
            (false, "created".into())
        );
        let (active, state) = batch_active_state(&pool, "bt-m").await;
        assert!(active);
        assert_eq!(state, "created");
        let qty: (i64,) = sqlx::query_as("SELECT quantity FROM batches WHERE id = 'bt-m'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(qty.0, 50, "合并数量守恒");
        let parents: (i64,) =
            sqlx::query_as("SELECT count(*) FROM batch_lineage WHERE child = 'bt-m'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(parents.0, 2);
        assert_eq!(
            ownership_row(&pool, "batch:bt-m").await,
            (enterprise.to_string(), 0, 0)
        );
    }

    /// 单品建档：Asset 落库 + outbox + 所有权建档（manufacturer 归属）。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn create_item_persists_asset_and_ownership(pool: sqlx::PgPool) {
        let maker = did("did:vg:user:ent-maker");
        use vg_domain::identity::capability::Action as Cap;
        seed_enterprise(&pool, &maker, &[Cap::CreateBatch]).await;
        seed_product(&pool, "pd-bag").await;
        let eng = engine(pool.clone());

        let commitment = Hash32::keccak(b"asset-cmt-1");
        let payload = serde_json::json!({
            "subject": {"type": "asset", "id": "as-1"},
            "product_id": "pd-bag",
            "authenticity_commitment": commitment.to_string()
        });
        let r = eng
            .execute(raw("i-1", IntentAction::CreateItem, &maker, payload.clone()))
            .await
            .unwrap();
        assert_eq!(r.status, IntentStatus::Confirmed);
        assert_eq!(r.result_ref.as_deref(), Some("as-1"));
        assert_eq!(outbox_types(&pool, "i-1").await, vec!["asset_created"]);
        let asset: (String, String) = sqlx::query_as(
            "SELECT state, manufacturer FROM assets WHERE id = 'as-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(asset, ("created".into(), maker.to_string()));
        assert_eq!(
            ownership_row(&pool, "asset:as-1").await,
            (maker.to_string(), 0, 0)
        );

        // 重复建档 → AlreadyExists 拒绝
        let dup = eng
            .execute(raw("i-2", IntentAction::CreateItem, &maker, payload))
            .await
            .unwrap();
        assert_eq!(dup.status, IntentStatus::Rejected);
        assert!(dup.rejection.as_deref().is_some_and(|x| x.contains("资源已存在")));
    }

    /// 缺凭证 → PolicyViolated 拒绝（Created→Produced 无 ProductionLicense）。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn missing_license_policy_rejects(pool: sqlx::PgPool) {
        let enterprise = did("did:vg:user:ent-novc");
        use vg_domain::identity::capability::Action as Cap;
        seed_enterprise(&pool, &enterprise, &[Cap::CreateBatch]).await;
        seed_product(&pool, "pd-pork").await;
        seed_policies(&pool).await;
        // 不 seed 任何 VC
        let eng = engine(pool.clone());

        let r = eng
            .execute(raw(
                "n-1",
                IntentAction::CreateBatch,
                &enterprise,
                serde_json::json!({
                    "subject": batch_subject("bt-novc"),
                    "product_id": "pd-pork", "quantity": 10, "unit": "kg",
                    "target_state": "produced"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(r.status, IntentStatus::Rejected);
        assert!(
            r.rejection
                .as_deref()
                .is_some_and(|x| x.contains("production_license")),
            "实际：{:?}",
            r.rejection
        );
        // 拒绝审计资源来自 payload subject（对象形编码 batch:bt-novc）
        let deny: (String,) = sqlx::query_as(
            "SELECT resource FROM audit_events WHERE intent_id = 'n-1' AND result = 'deny'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(deny.0, "batch:bt-novc");
        // 业务写入整体回滚：批次不落库
        let none: (i64,) = sqlx::query_as("SELECT count(*) FROM batches WHERE id = 'bt-novc'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(none.0, 0);
    }

    /// 转移拒绝路径抽查：自转（合约 invalid target）与未建档主体。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn transfer_self_and_uninitialized_rejected(pool: sqlx::PgPool) {
        let enterprise = did("did:vg:user:ent-rej");
        use vg_domain::identity::capability::Action as Cap;
        seed_enterprise(&pool, &enterprise, &[Cap::CreateBatch, Cap::TransferOwnership]).await;
        seed_product(&pool, "pd-pork").await;
        let eng = engine(pool.clone());

        eng.execute(raw(
            "r-0",
            IntentAction::CreateBatch,
            &enterprise,
            serde_json::json!({
                "subject": batch_subject("bt-r"),
                "product_id": "pd-pork", "quantity": 5, "unit": "kg"
            }),
        ))
        .await
        .unwrap();

        // 自转：转给当前所有者自己
        let self_r = eng
            .execute(raw(
                "r-1",
                IntentAction::TransferProduct,
                &enterprise,
                serde_json::json!({
                    "subject": batch_subject("bt-r"),
                    "to": enterprise.to_string(), "c2c": false
                }),
            ))
            .await
            .unwrap();
        assert_eq!(self_r.status, IntentStatus::Rejected);
        assert!(
            self_r
                .rejection
                .as_deref()
                .is_some_and(|x| x.contains("非法状态迁移"))
        );

        // 未建档主体：从未 create 的批次直接转移
        let no_owner = eng
            .execute(raw(
                "r-2",
                IntentAction::TransferProduct,
                &enterprise,
                serde_json::json!({
                    "subject": batch_subject("bt-ghost"),
                    "to": did("did:vg:user:whoever").to_string(), "c2c": false
                }),
            ))
            .await
            .unwrap();
        assert_eq!(no_owner.status, IntentStatus::Rejected);
        assert!(
            no_owner
                .rejection
                .as_deref()
                .is_some_and(|x| x.contains("所有权档案"))
        );
    }
}
