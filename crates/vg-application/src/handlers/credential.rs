//! Task 22 凭证处理器：IssueCredential / RevokeCredential。
//!
//! 联动契约（doc 锁定）：
//! - **issue**：issuer = effective principal（Agent 代发时为被代理主体），
//!   VC 构造（`credential_hash` 由领域自动计算）→ 可选 schema 校验 →
//!   落库 → [`recompute_compliance`]（重签发补齐凭证可触发召回恢复）→
//!   outbox `CredentialIssued` → **`ledger.anchor`（最后，悬挂锚契约）**；
//! - **revoke**：领域 issuer-only 状态机（非签发方 → Unauthorized）→
//!   乐观锁落库 → [`recompute_compliance`]（凭证缺失触发强制召回）→
//!   outbox `CredentialRevoked` → **`ledger.anchor`（最后）**；
//! - 两次锚定均为 [`LedgerItem::CredentialStatus`]（issue=Valid、
//!   revoke=Revoked），消费方以链上锚定记录核对凭证状态。
//!
//! **schema 匹配口径（Phase1）**：辖区 → 监管域无查询端口，payload 以
//! 可选 `domain_id` 显式指定；未指定时跳过 schema 校验（可无域签发），
//! 类型匹配的强约束在 revoke/compliance 重算侧生效——required_credentials
//! 按 ctype 精确匹配，schema 缺 claims 只影响签发时的形状校验。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use vg_domain::credential::{CredStatus, VerifiableCredential};
use vg_domain::events::DomainEvent;
use vg_domain::intent::{Intent, IntentAction};
use vg_domain::ports::LedgerItem;
use vg_domain::shared::{CredentialId, Did, DomainError, SubjectRef};

use crate::deps::{AppDeps, PgTx};
use crate::handlers::{effective_principal, parse_payload, subject_label};
use crate::intent_engine::{HandlerOutcome, IntentHandler};
use crate::services::compliance::recompute_compliance;

/// IssueCredential 载荷。
///
/// JSON Schema（`deny_unknown_fields`，subject 必填为审计兜底）：
///
/// ```json
/// {
///   "subject":  {"type": "batch", "id": "bt-001"},
///   "holder":   "did:vg:user:ent-farm",
///   "ctype":    "food_safety_inspection",
///   "claims":   {"result": "passed"},
///   "expires_at": "2027-01-01T00:00:00Z",
///   "credential_id": "vc-042",
///   "domain_id": "vg:domain:cn-food@v1"
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuePayload {
    /// 关联批次/单品（审计与合规重算入口；VC 本身不持有该字段）。
    subject: SubjectRef,
    /// VC 受证人（凭证持有企业——合规检核按该主体口径匹配）。
    holder: Did,
    /// 凭证类型（serde 即 12 类 snake_case）。
    ctype: vg_domain::credential::CredentialType,
    /// 主体声明集合（必须为 JSON object，领域构造强制）。
    claims: serde_json::Value,
    /// 过期时刻；缺省长期有效。
    expires_at: Option<DateTime<Utc>>,
    /// 凭证 ID；缺省自动生成。
    credential_id: Option<CredentialId>,
    /// 监管域 ID；提供时对 ctype 匹配的 schema 做 required_claims 校验。
    domain_id: Option<String>,
}

/// RevokeCredential 载荷。
///
/// JSON Schema（`deny_unknown_fields`）：
///
/// ```json
/// {
///   "subject":       {"type": "batch", "id": "bt-001"},
///   "credential_id": "vc-042",
///   "reason":        "检测复检不合格"
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokePayload {
    /// 关联批次/单品（撤销后的合规重算入口）。
    subject: SubjectRef,
    /// 目标凭证。
    credential_id: CredentialId,
    /// 撤销原因（审计留痕：结构化日志一行；Phase1 不入领域事件体）。
    reason: Option<String>,
}

/// 签发凭证处理器。
pub struct IssueCredentialHandler;

#[async_trait]
impl IntentHandler for IssueCredentialHandler {
    fn action(&self) -> IntentAction {
        IntentAction::IssueCredential
    }

    async fn handle(
        &self,
        deps: &AppDeps,
        tx: &mut PgTx,
        intent: &mut Intent,
        now: DateTime<Utc>,
    ) -> Result<HandlerOutcome, DomainError> {
        let payload: IssuePayload = parse_payload(intent)?;
        let issuer = effective_principal(intent);

        // 可选 schema 校验：指定 domain_id 时按 ctype 匹配 schema，
        // 命中则校验 required_claims（缺键 → InvalidInput）；域内无该
        // ctype 的 schema 时视同未指定（Phase1 不强制全类型配模）。
        if let Some(domain_id) = &payload.domain_id {
            if let Some(domain) = deps.policies.find_domain(tx, domain_id).await? {
                if let Some(schema) = domain
                    .credential_schemas
                    .iter()
                    .find(|s| s.ctype == payload.ctype)
                {
                    schema.validate_claims(&payload.claims)?;
                }
            } else {
                return Err(DomainError::InvalidInput(format!(
                    "监管域不存在：{domain_id}"
                )));
            }
        }

        // VC 构造：credential_hash 由领域自动计算并锁定（golden vector）
        let id = payload.credential_id.clone().unwrap_or_else(CredentialId::generate);
        let vc = VerifiableCredential::new(
            id.clone(),
            issuer.clone(),
            payload.holder.clone(),
            payload.ctype,
            payload.claims,
            now,
            payload.expires_at,
        )?;
        // credential_hash UNIQUE：内容重复（同 id/同内容重签）→ 语义化为
        // 输入错误提示重复，而非裸存储冲突
        if let Err(e) = deps.credentials.save(tx, &vc).await {
            if matches!(e, DomainError::AlreadyExists) {
                return Err(DomainError::InvalidInput(format!(
                    "凭证内容重复（credential_hash 冲突）：{id}"
                )));
            }
            return Err(e);
        }

        // 重签发联动：凭证补齐可能触发召回恢复（Recalled→Available）
        recompute_compliance(deps, tx, &payload.subject, &intent.id, now).await?;

        // outbox（锚定前完成；恢复/召回事件已由 recompute 落入同 aggregate）
        deps.outbox
            .append(
                tx,
                &format!("intent:{}", intent.id.as_ref()),
                &DomainEvent::CredentialIssued {
                    credential: id.clone(),
                    issuer,
                    subject: payload.holder.clone(),
                },
            )
            .await?;

        // 悬挂锚：最后锚定签发状态
        deps.ledger
            .anchor(LedgerItem::CredentialStatus {
                id: id.clone(),
                hash: vc.credential_hash,
                status: CredStatus::Valid,
            })
            .await?;

        Ok(HandlerOutcome::Completed {
            result_ref: id.to_string(),
            resource: subject_label(&payload.subject),
            policy: vec![],
            proof_id: None,
        })
    }
}

/// 撤销凭证处理器。
pub struct RevokeCredentialHandler;

#[async_trait]
impl IntentHandler for RevokeCredentialHandler {
    fn action(&self) -> IntentAction {
        IntentAction::RevokeCredential
    }

    async fn handle(
        &self,
        deps: &AppDeps,
        tx: &mut PgTx,
        intent: &mut Intent,
        now: DateTime<Utc>,
    ) -> Result<HandlerOutcome, DomainError> {
        let payload: RevokePayload = parse_payload(intent)?;
        let actor = effective_principal(intent);

        // 撤销原因审计留痕（Phase1 不入领域事件体，结构化日志兜底）
        tracing::info!(
            credential = %payload.credential_id,
            reason = payload.reason.as_deref().unwrap_or(""),
            "撤销凭证"
        );

        // 领域状态机：仅签发方可撤销（非 issuer → Unauthorized）
        let mut vc = deps
            .credentials
            .find(tx, &payload.credential_id)
            .await?
            .ok_or(DomainError::NotFound)?;
        let expected = vc.status;
        vc.transition(CredStatus::Revoked, &actor, now)?;
        // 乐观锁落库（expected=撤销前状态；0 行/状态漂移 → 透传错误）
        deps.credentials
            .update_status(tx, &payload.credential_id, expected, CredStatus::Revoked, now)
            .await?;

        // 撤销联动：缺失必需凭证 → 强制召回（三分支规则见 services::compliance）
        recompute_compliance(deps, tx, &payload.subject, &intent.id, now).await?;

        // outbox（锚定前完成；召回事件已由 recompute 落入同 aggregate）
        deps.outbox
            .append(
                tx,
                &format!("intent:{}", intent.id.as_ref()),
                &DomainEvent::CredentialRevoked {
                    credential: payload.credential_id.clone(),
                    by: actor,
                },
            )
            .await?;

        // 悬挂锚：最后锚定撤销状态（内容哈希不变，status 不参与哈希）
        deps.ledger
            .anchor(LedgerItem::CredentialStatus {
                id: payload.credential_id.clone(),
                hash: vc.credential_hash,
                status: CredStatus::Revoked,
            })
            .await?;

        Ok(HandlerOutcome::Completed {
            result_ref: payload.credential_id.to_string(),
            resource: subject_label(&payload.subject),
            policy: vec![],
            proof_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Task 22 e2e 测试（sqlx::test，与 handlers/mod.rs 同风格）。
    //!
    //! 主线：FoodSafety VC 撤销 → 批次自动 RECALLED → 重签发 → 经 policy
    //! 恢复边自动恢复 Available；另覆盖只读查询、schema 校验、重复哈希、
    //! 非 issuer 撤销与重复召回幂等。

    use super::*;
    use vg_domain::commodity::ports::CommodityRepository;
    use vg_domain::credential::ports::CredentialRepository;
    use vg_domain::credential::CredentialType;
    use vg_domain::identity::ports::IdentityRepository;
    use vg_domain::identity::{
        Capability, DidDocument, KeyType, SubjectKind, VerificationMethod,
    };
    use vg_domain::intent::{IntentStatus, RiskLevel};
    use vg_domain::lifecycle::LifecycleState;
    use vg_domain::ownership::ports::OwnershipRepository;
    use vg_domain::ownership::OwnershipState;
    use vg_domain::policy::ports::PolicyRepository;
    use vg_domain::policy::{Policy, RegulatoryDomain};
    use vg_domain::shared::{Hash32, IntentId, PolicyId, ProductId};
    use vg_infra_pg::{
        InProcessLedger, PgApprovalsStore, PgAuditWriter, PgCommodityRepo, PgCredentialRepo,
        PgIdentityRepo, PgIntentRepository, PgLifecycleRepo, PgOutbox, PgOwnershipRepo,
        PgPolicyRepository, PgProofStore,
    };

    struct StubProver;
    #[async_trait]
    impl vg_domain::ports::ProofProver for StubProver {
        async fn prove(
            &self,
            circuit: &vg_domain::ports::CircuitSpec,
            _witness: &vg_domain::ports::Witness,
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
    impl vg_domain::ports::NoteHasher for StubHasher {
        fn note_commitment(&self, parts: &[[u8; 32]]) -> Hash32 {
            Hash32::keccak(&parts.concat())
        }
    }

    // ---- fixture ----

    fn did(s: &str) -> Did {
        Did::parse(s).unwrap()
    }

    fn doc(did_value: Did, jurisdiction: Option<String>) -> DidDocument {
        DidDocument {
            did: did_value.clone(),
            kind: SubjectKind::Enterprise,
            methods: vec![VerificationMethod::new(
                "k-0",
                KeyType::Secp256k1,
                Hash32::keccak(b"pk"),
                did_value,
            )],
            parent: None,
            jurisdiction,
            created_at: Utc::now(),
        }
    }

    fn deps(pool: sqlx::PgPool) -> AppDeps {
        AppDeps {
            pool: pool.clone(),
            identity: std::sync::Arc::new(PgIdentityRepo),
            credentials: std::sync::Arc::new(PgCredentialRepo),
            commodity: std::sync::Arc::new(PgCommodityRepo),
            ownership: std::sync::Arc::new(PgOwnershipRepo),
            lifecycle: std::sync::Arc::new(PgLifecycleRepo),
            policies: std::sync::Arc::new(PgPolicyRepository),
            intents: std::sync::Arc::new(PgIntentRepository),
            proofs: std::sync::Arc::new(PgProofStore),
            audit: std::sync::Arc::new(PgAuditWriter),
            outbox: std::sync::Arc::new(PgOutbox),
            approvals: std::sync::Arc::new(PgApprovalsStore),
            ledger: std::sync::Arc::new(InProcessLedger::new(pool)),
            prover: std::sync::Arc::new(StubProver),
            hasher: std::sync::Arc::new(StubHasher),
        }
    }

    fn engine(pool: sqlx::PgPool) -> crate::intent_engine::IntentEngine {
        let mut map = crate::intent_engine::HandlerMap::new();
        crate::handlers::register_default(&mut map);
        crate::intent_engine::IntentEngine::new(deps(pool), map)
    }

    /// 全量 fixture：监管者（issuer/revoker）、企业（holder/owner）、
    /// food 商品类目、CN×food 策略（required=food_safety_inspection，
    /// 含 (recalled,available) 恢复边）、监管域 schema、Available 批次
    /// + 所有权（owner=企业）。
    async fn seed(pool: &sqlx::PgPool) -> (Did, Did) {
        use vg_domain::identity::capability::Action as Cap;
        let regulator = did("did:vg:user:regulator-t22");
        let enterprise = did("did:vg:user:ent-t22");
        let mut tx = pool.begin().await.unwrap();
        let identity = PgIdentityRepo;
        identity
            .save_document(&mut tx, &doc(regulator.clone(), Some("CN".into())))
            .await
            .unwrap();
        identity
            .save_document(&mut tx, &doc(enterprise.clone(), Some("CN".into())))
            .await
            .unwrap();
        let grantor = did("did:vg:user:grantor-t22");
        identity
            .save_document(&mut tx, &doc(grantor.clone(), Some("CN".into())))
            .await
            .unwrap();
        for cap in [Cap::IssueCredential, Cap::RevokeCredential] {
            identity
                .grant_capability(
                    &mut tx,
                    &Capability::new(regulator.clone(), cap, grantor.clone(), None).unwrap(),
                )
                .await
                .unwrap();
        }
        // 商品类目 food
        PgCommodityRepo
            .save_product(
                &mut tx,
                &vg_domain::commodity::ProductType::new(
                    ProductId::new("pd-food"),
                    "food",
                    Hash32::keccak(b"food-meta"),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        // 策略：required = food_safety_inspection；恢复边 (recalled,available)
        PgPolicyRepository
            .save_policy(
                &mut tx,
                &Policy {
                    policy_id: PolicyId::new("pol-food-safety"),
                    version: 2,
                    authority: regulator.clone(),
                    jurisdiction: "CN".into(),
                    product_type: "food".into(),
                    required_credentials: vec![CredentialType::FoodSafetyInspection],
                    required_proofs: vec![],
                    transitions: vec![(
                        LifecycleState::Recalled,
                        LifecycleState::Available,
                    )],
                    effective_at: Utc::now() - chrono::Duration::days(1),
                    expires_at: None,
                    active: true,
                },
            )
            .await
            .unwrap();
        // 监管域：food_safety schema 必需 claims = ["result"]
        PgPolicyRepository
            .save_domain(
                &mut tx,
                &RegulatoryDomain {
                    domain_id: "dom-cn-food".into(),
                    authority: regulator.clone(),
                    jurisdiction: "CN".into(),
                    product_types: vec!["food".into()],
                    credential_schemas: vec![vg_domain::credential::CredentialSchema {
                        id: "vg:schema:food-safety@v1".into(),
                        ctype: CredentialType::FoodSafetyInspection,
                        required_claims: vec!["result".into()],
                    }],
                    effective_from: Utc::now() - chrono::Duration::days(1),
                },
            )
            .await
            .unwrap();
        // Available 批次 + 所有权（owner=企业）
        let mut batch = vg_domain::commodity::Batch::new(
            vg_domain::shared::BatchId::new("bt-food"),
            ProductId::new("pd-food"),
            10,
            "kg",
            Utc::now() - chrono::Duration::days(1),
            enterprise.clone(),
        )
        .unwrap();
        batch.state = LifecycleState::Available;
        PgCommodityRepo.save_batch(&mut tx, &batch).await.unwrap();
        PgOwnershipRepo
            .init_owner(
                &mut tx,
                &OwnershipState::initialize(
                    SubjectRef::Batch(vg_domain::shared::BatchId::new("bt-food")),
                    enterprise.clone(),
                    Utc::now() - chrono::Duration::days(1),
                ),
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (regulator, enterprise)
    }

    fn raw(
        id: &str,
        action: IntentAction,
        actor: &Did,
        payload: serde_json::Value,
    ) -> crate::intent_engine::RawIntent {
        use std::sync::atomic::{AtomicU64, Ordering};
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

    async fn batch_state(pool: &sqlx::PgPool, id: &str) -> (bool, String) {
        sqlx::query_as("SELECT active, state FROM batches WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn batch_compliance(pool: &sqlx::PgPool, id: &str) -> bool {
        let (ok,): (bool,) = sqlx::query_as("SELECT compliance_ok FROM batches WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
        ok
    }

    async fn cred_status(pool: &sqlx::PgPool, id: &str) -> String {
        let (s,): (String,) = sqlx::query_as("SELECT status FROM credentials WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
        s
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

    async fn lifecycle_chain(
        pool: &sqlx::PgPool,
        subject: &str,
    ) -> Vec<(String, String, Option<String>, Option<i64>)> {
        sqlx::query_as(
            "SELECT from_state, to_state, reason, policy_version FROM lifecycle_events \
             WHERE subject = $1 ORDER BY at ASC, id ASC",
        )
        .bind(subject)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    async fn anchors(pool: &sqlx::PgPool, kind: &str) -> i64 {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM ledger_anchors WHERE kind = $1",
        )
        .bind(kind)
        .fetch_one(pool)
        .await
        .unwrap();
        n
    }

    /// 主线（plan 必测）：撤销 → 自动召回；重签发 → 恢复 Available。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn revoke_triggers_recall_and_reissue_restores(pool: sqlx::PgPool) {
        let (regulator, enterprise) = seed(&pool).await;
        let app = deps(pool.clone());
        let eng = engine(pool.clone());

        // 前置：签发 FoodSafety VC（经 handler，锚定 issue 事件）
        let issue = eng
            .execute(raw(
                "c-1",
                IntentAction::IssueCredential,
                &regulator,
                serde_json::json!({
                    "subject": batch_subject("bt-food"),
                    "holder": enterprise.to_string(),
                    "ctype": "food_safety_inspection",
                    "claims": {"result": "passed", "score": 96},
                    "credential_id": "vc-food-1"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(issue.status, IntentStatus::Confirmed);
        assert_eq!(issue.result_ref.as_deref(), Some("vc-food-1"));
        assert_eq!(issue.risk, RiskLevel::L2, "凭证签撤为企业策略自动批准级");
        assert_eq!(cred_status(&pool, "vc-food-1").await, "valid");
        assert_eq!(outbox_types(&pool, "c-1").await, vec!["credential_issued"]);
        assert_eq!(anchors(&pool, "credential_status").await, 1);
        // 签发时凭证已齐备且状态 Available：无状态迁移
        assert_eq!(batch_state(&pool, "bt-food").await, (true, "available".into()));

        // 撤销 → 缺失 food_safety_inspection → 强制召回
        let revoke = eng
            .execute(raw(
                "c-2",
                IntentAction::RevokeCredential,
                &regulator,
                serde_json::json!({
                    "subject": batch_subject("bt-food"),
                    "credential_id": "vc-food-1",
                    "reason": "复检不合格"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(revoke.status, IntentStatus::Confirmed);
        assert_eq!(revoke.result_ref.as_deref(), Some("vc-food-1"));
        assert_eq!(cred_status(&pool, "vc-food-1").await, "revoked");
        // active 位不动（可售语义属 Delisted 开关），状态 → recalled
        assert_eq!(batch_state(&pool, "bt-food").await, (true, "recalled".into()));
        assert!(
            !batch_compliance(&pool, "bt-food").await,
            "召回联动回写 compliance_ok = false"
        );
        let mut evs = outbox_types(&pool, "c-2").await;
        evs.sort();
        assert_eq!(evs, vec!["credential_revoked", "product_recalled"]);
        assert_eq!(anchors(&pool, "credential_status").await, 2, "issue+revoke 各一");
        let chain = lifecycle_chain(&pool, "batch:bt-food").await;
        assert_eq!(chain.len(), 1);
        assert_eq!(
            (chain[0].0.as_str(), chain[0].1.as_str()),
            ("available", "recalled")
        );
        assert!(
            chain[0]
                .2
                .as_deref()
                .is_some_and(|r| r.contains("food_safety_inspection")),
            "reason 应列出缺失凭证：{:?}",
            chain[0].2
        );
        assert_eq!(chain[0].3, None, "召回不经 policy 批准");

        // 重签发同 ctype 新 VC → 恢复路径（policy 含恢复边 + 凭证满足）
        let reissue = eng
            .execute(raw(
                "c-3",
                IntentAction::IssueCredential,
                &regulator,
                serde_json::json!({
                    "subject": batch_subject("bt-food"),
                    "holder": enterprise.to_string(),
                    "ctype": "food_safety_inspection",
                    "claims": {"result": "passed"},
                    "credential_id": "vc-food-2"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(reissue.status, IntentStatus::Confirmed);
        assert_eq!(
            batch_state(&pool, "bt-food").await,
            (true, "available".into()),
            "凭证补齐 + policy 恢复边 → 自动恢复 Available"
        );
        assert!(
            batch_compliance(&pool, "bt-food").await,
            "恢复联动回写 compliance_ok = true"
        );
        let mut evs = outbox_types(&pool, "c-3").await;
        evs.sort();
        assert_eq!(evs, vec!["compliance_changed", "credential_issued"]);
        let chain = lifecycle_chain(&pool, "batch:bt-food").await;
        assert_eq!(chain.len(), 2);
        assert_eq!(
            (chain[1].0.as_str(), chain[1].1.as_str()),
            ("recalled", "available")
        );
        assert_eq!(chain[1].3, Some(2), "恢复事件 policy_version=enforced 版本");

        // 只读检查收尾：合规无缺失
        let report = crate::services::compliance::check_compliance(
            &app,
            &SubjectRef::Batch(vg_domain::shared::BatchId::new("bt-food")),
        )
        .await
        .unwrap();
        assert!(report.compliant);
        assert!(report.missing.is_empty());
    }

    /// check_compliance 只读：撤销前查询缺失应为空；撤销后不触发迁移由
    /// 主线覆盖，此处验证先查后撤的顺序下查询本身零状态副作用。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn check_compliance_is_readonly(pool: sqlx::PgPool) {
        let (regulator, _enterprise) = seed(&pool).await;
        let app = deps(pool.clone());
        let subject = SubjectRef::Batch(vg_domain::shared::BatchId::new("bt-food"));

        // 尚无任何 VC：缺失 food_safety_inspection，状态保持 available
        let report = crate::services::compliance::check_compliance(&app, &subject)
            .await
            .unwrap();
        assert!(!report.compliant);
        assert_eq!(report.missing, vec![CredentialType::FoodSafetyInspection]);
        assert_eq!(
            batch_state(&pool, "bt-food").await,
            (true, "available".into()),
            "只读查询不得触发状态迁移"
        );
        assert!(lifecycle_chain(&pool, "batch:bt-food").await.is_empty());

        // 必需凭证并集查询：active 过滤后命中
        let required = crate::services::compliance::get_required_credentials(&app, &subject)
            .await
            .unwrap();
        assert_eq!(required, vec![CredentialType::FoodSafetyInspection]);

        // 过期策略的凭证需求不计入：补一条已过期策略 required=quality_inspection
        let mut tx = pool.begin().await.unwrap();
        PgPolicyRepository
            .save_policy(
                &mut tx,
                &Policy {
                    policy_id: PolicyId::new("pol-expired"),
                    version: 1,
                    authority: regulator.clone(),
                    jurisdiction: "CN".into(),
                    product_type: "food".into(),
                    required_credentials: vec![CredentialType::QualityInspection],
                    required_proofs: vec![],
                    transitions: vec![],
                    effective_at: Utc::now() - chrono::Duration::days(10),
                    expires_at: Some(Utc::now() - chrono::Duration::days(1)),
                    active: true,
                },
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let required = crate::services::compliance::get_required_credentials(&app, &subject)
            .await
            .unwrap();
        assert_eq!(
            required,
            vec![CredentialType::FoodSafetyInspection],
            "已过期策略的需求不计入并集"
        );
    }

    /// schema 匹配路径：domain_id 提供且 claims 缺 required_claims → 拒绝；
    /// domain_id 不存在 → 拒绝；未提供 domain_id → 跳过校验（空 claims 通过）。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn issue_schema_validation_paths(pool: sqlx::PgPool) {
        let (regulator, enterprise) = seed(&pool).await;
        let eng = engine(pool.clone());

        let bad = eng
            .execute(raw(
                "v-1",
                IntentAction::IssueCredential,
                &regulator,
                serde_json::json!({
                    "subject": batch_subject("bt-food"),
                    "holder": enterprise.to_string(),
                    "ctype": "food_safety_inspection",
                    "claims": {"score": 96},
                    "credential_id": "vc-schema-bad",
                    "domain_id": "dom-cn-food"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(bad.status, IntentStatus::Rejected);
        assert!(
            bad.rejection
                .as_deref()
                .is_some_and(|r| r.contains("result")),
            "缺 required_claims 键：{:?}",
            bad.rejection
        );

        let ghost = eng
            .execute(raw(
                "v-2",
                IntentAction::IssueCredential,
                &regulator,
                serde_json::json!({
                    "subject": batch_subject("bt-food"),
                    "holder": enterprise.to_string(),
                    "ctype": "food_safety_inspection",
                    "claims": {"result": "ok"},
                    "domain_id": "dom-nope"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(ghost.status, IntentStatus::Rejected);
        assert!(
            ghost
                .rejection
                .as_deref()
                .is_some_and(|r| r.contains("监管域不存在"))
        );

        // 无 domain_id：Phase1 可无域签发，claims 形状不做 schema 校验
        let free = eng
            .execute(raw(
                "v-3",
                IntentAction::IssueCredential,
                &regulator,
                serde_json::json!({
                    "subject": batch_subject("bt-food"),
                    "holder": enterprise.to_string(),
                    "ctype": "origin",
                    "claims": {},
                    "credential_id": "vc-free"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(free.status, IntentStatus::Confirmed);
        assert_eq!(cred_status(&pool, "vc-free").await, "valid");
    }

    /// 重复内容（不同 id、同其余字段）→ credential_hash UNIQUE 冲突；
    /// 非 issuer 撤销 → Unauthorized。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn duplicate_hash_and_non_issuer_revoke_rejected(pool: sqlx::PgPool) {
        let (regulator, enterprise) = seed(&pool).await;
        let eng = engine(pool.clone());

        let first = eng
            .execute(raw(
                "d-1",
                IntentAction::IssueCredential,
                &regulator,
                serde_json::json!({
                    "subject": batch_subject("bt-food"),
                    "holder": enterprise.to_string(),
                    "ctype": "food_safety_inspection",
                    "claims": {"result": "passed"},
                    "credential_id": "vc-dup"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(first.status, IntentStatus::Confirmed);

        // 非 issuer 撤销：actor=企业（授 RevokeCredential 能力，通过 engine
        // 能力段）≠ 签发方 → 领域规则拒绝
        {
            use vg_domain::identity::capability::Action as Cap;
            let mut tx = pool.begin().await.unwrap();
            let grantor = did("did:vg:user:grantor-t22");
            PgIdentityRepo
                .grant_capability(
                    &mut tx,
                    &Capability::new(
                        enterprise.clone(),
                        Cap::RevokeCredential,
                        grantor,
                        None,
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        let steal = eng
            .execute(raw(
                "d-2",
                IntentAction::RevokeCredential,
                &enterprise,
                serde_json::json!({
                    "subject": batch_subject("bt-food"),
                    "credential_id": "vc-dup"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(steal.status, IntentStatus::Rejected);
        assert!(
            steal
                .rejection
                .as_deref()
                .is_some_and(|r| r.contains("仅签发方")),
            "非 issuer 撤销应被领域规则拒绝：{:?}",
            steal.rejection
        );
        // 凭证状态未被改动，无召回
        assert_eq!(cred_status(&pool, "vc-dup").await, "valid");
        assert_eq!(batch_state(&pool, "bt-food").await, (true, "available".into()));

        // credential_hash / id 重复：同一 VC（含 issued_at 完全一致 → 哈希
        // 一致）直接 save 两次 → UNIQUE 冲突（handler 侧该错误被语义化为
        // InvalidInput 提示重复，仓储行为在此直接钉死）
        {
            let mut tx = pool.begin().await.unwrap();
            let t = Utc::now() - chrono::Duration::days(1);
            let vc = VerifiableCredential::new(
                CredentialId::new("vc-orig"),
                regulator.clone(),
                enterprise.clone(),
                CredentialType::FoodSafetyInspection,
                serde_json::json!({"result": "passed"}),
                t,
                Some(t + chrono::Duration::days(365)),
            )
            .unwrap();
            PgCredentialRepo.save(&mut tx, &vc).await.unwrap();
            let err = PgCredentialRepo.save(&mut tx, &vc).await.unwrap_err();
            assert!(
                matches!(err, DomainError::AlreadyExists),
                "同 id 同内容重复保存应报已存在：{err:?}"
            );
            tx.rollback().await.unwrap();
        }
    }

    /// 批次已在 Recalled（另一 VC 撤销触发）后再撤销第二个 VC：
    /// 不重复迁移（事件不双发、outbox 不重复召回）。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn revoke_when_already_recalled_is_idempotent(pool: sqlx::PgPool) {
        let (regulator, enterprise) = seed(&pool).await;
        let eng = engine(pool.clone());

        // vc-a = 策略必需类型；vc-b = 无关类型（撤销它不改变缺失集合）
        for (id, ctype) in [("vc-a", "food_safety_inspection"), ("vc-b", "origin")] {
            eng.execute(raw(
                &format!("i-{id}"),
                IntentAction::IssueCredential,
                &regulator,
                serde_json::json!({
                    "subject": batch_subject("bt-food"),
                    "holder": enterprise.to_string(),
                    "ctype": ctype,
                    "claims": {"result": "passed"},
                    "credential_id": id
                }),
            ))
            .await
            .unwrap();
        }
        // 第一撤销 → 召回
        eng.execute(raw(
            "r-a",
            IntentAction::RevokeCredential,
            &regulator,
            serde_json::json!({
                "subject": batch_subject("bt-food"),
                "credential_id": "vc-a"
            }),
        ))
        .await
        .unwrap();
        assert_eq!(batch_state(&pool, "bt-food").await, (true, "recalled".into()));

        // 第二撤销（凭证本已缺失，状态已 Recalled）→ 不再迁移/不双发
        let second = eng
            .execute(raw(
                "r-b",
                IntentAction::RevokeCredential,
                &regulator,
                serde_json::json!({
                    "subject": batch_subject("bt-food"),
                    "credential_id": "vc-b"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(second.status, IntentStatus::Confirmed);
        assert_eq!(cred_status(&pool, "vc-b").await, "revoked");
        assert_eq!(
            outbox_types(&pool, "r-b").await,
            vec!["credential_revoked"],
            "已召回状态下二次撤销不再发 product_recalled"
        );
        assert_eq!(
            lifecycle_chain(&pool, "batch:bt-food").await.len(),
            1,
            "迁移事件不双发"
        );
    }

    /// 恢复门关闭：凭证齐全但策略无 (recalled, available) 恢复边 →
    /// 保持 Recalled，且 outbox 出现 compliant:false 的 ComplianceChanged
    /// 观测事件（闭环不静默）。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn restore_gate_closed_keeps_recalled_and_signals(pool: sqlx::PgPool) {
        let (regulator, enterprise) = seed(&pool).await;
        let eng = engine(pool.clone());

        // 覆盖策略：同 (policy_id, version) 覆盖式 upsert，去掉恢复边
        {
            let mut tx = pool.begin().await.unwrap();
            PgPolicyRepository
                .save_policy(
                    &mut tx,
                    &Policy {
                        policy_id: PolicyId::new("pol-food-safety"),
                        version: 2,
                        authority: regulator.clone(),
                        jurisdiction: "CN".into(),
                        product_type: "food".into(),
                        required_credentials: vec![CredentialType::FoodSafetyInspection],
                        required_proofs: vec![],
                        transitions: vec![], // 恢复边移除
                        effective_at: Utc::now() - chrono::Duration::days(1),
                        expires_at: None,
                        active: true,
                    },
                )
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }

        // 签发 → 撤销（强制召回）
        eng.execute(raw(
            "g-1",
            IntentAction::IssueCredential,
            &regulator,
            serde_json::json!({
                "subject": batch_subject("bt-food"),
                "holder": enterprise.to_string(),
                "ctype": "food_safety_inspection",
                "claims": {"result": "passed"},
                "credential_id": "vc-gate-1"
            }),
        ))
        .await
        .unwrap();
        eng.execute(raw(
            "g-2",
            IntentAction::RevokeCredential,
            &regulator,
            serde_json::json!({
                "subject": batch_subject("bt-food"),
                "credential_id": "vc-gate-1"
            }),
        ))
        .await
        .unwrap();
        assert_eq!(batch_state(&pool, "bt-food").await, (true, "recalled".into()));

        // 重签发 → 凭证齐备但无恢复边：保持 Recalled + compliant:false 事件
        let reissue = eng
            .execute(raw(
                "g-3",
                IntentAction::IssueCredential,
                &regulator,
                serde_json::json!({
                    "subject": batch_subject("bt-food"),
                    "holder": enterprise.to_string(),
                    "ctype": "food_safety_inspection",
                    "claims": {"result": "passed"},
                    "credential_id": "vc-gate-2"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(reissue.status, IntentStatus::Confirmed);
        assert_eq!(
            batch_state(&pool, "bt-food").await,
            (true, "recalled".into()),
            "无策略恢复边 → 恢复门关闭，保持 Recalled"
        );
        assert!(
            !batch_compliance(&pool, "bt-food").await,
            "恢复未发生，compliance_ok 不回写为 true"
        );
        // 闭环观测点：outbox 出现 compliant:false 的 compliance_changed
        let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
            "SELECT payload FROM domain_events WHERE aggregate = $1 ORDER BY id ASC",
        )
        .bind("intent:g-3")
        .fetch_all(&pool)
        .await
        .unwrap();
        let flags: Vec<bool> = rows
            .iter()
            .filter(|(p,)| p["event_type"].as_str() == Some("compliance_changed"))
            .map(|(p,)| p["compliant"].as_bool().unwrap())
            .collect();
        assert_eq!(flags, vec![false], "恢复门静默拒绝必须留 compliant:false 事件");

        // 生命周期只有一条召回迁移（无 restore）
        assert_eq!(lifecycle_chain(&pool, "batch:bt-food").await.len(), 1);
    }
}
