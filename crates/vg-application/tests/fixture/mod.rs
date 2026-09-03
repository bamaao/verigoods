//! e2e fixture：从 `handlers/mod.rs` / `credential.rs` / `shielded.rs` 的
//! `#[cfg(test)]` 测试段移植的公共 helper（集成测试无法引用库内测试
//! fixture，此处独立维护；口径与生产代码一致，仅做参数化泛化）。

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;

use vg_application::{AppDeps, IntentEngine, RawIntent};
use vg_domain::commodity::ports::CommodityRepository;
use vg_domain::credential::ports::CredentialRepository;
use vg_domain::credential::{CredentialType, VerifiableCredential};
use vg_domain::identity::ports::IdentityRepository;
use vg_domain::identity::{Capability, DidDocument, KeyType, VerificationMethod};
use vg_domain::intent::IntentAction;
use vg_domain::ownership::ports::OwnershipRepository;
use vg_domain::ownership::OwnershipState;
use vg_domain::policy::ports::PolicyRepository;
use vg_domain::policy::{Policy, RegulatoryDomain};
use vg_domain::ports::{CircuitSpec, NoteHasher, ProofProver, Witness};
use vg_domain::shared::{Did, DomainError, Hash32, IntentId, ProductId, SubjectRef};
use vg_infra_crypto::{KeyPair, PoseidonNoteHasher};
use vg_infra_pg::{
    InProcessLedger, PgApprovalsStore, PgAuditWriter, PgCommodityRepo, PgCredentialRepo,
    PgIdentityRepo, PgIntentRepository, PgLifecycleRepo, PgOutbox, PgOwnershipRepo,
    PgPolicyRepository, PgProofStore,
};
use vg_infra_zk::ProverDispatcher;

pub type PgTx = sqlx::Transaction<'static, sqlx::Postgres>;

// ---- 测试桩（与 handlers/mod.rs 测试同款；shielded 场景用真实组件） ----

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

fn deps_with(
    pool: &sqlx::PgPool,
    prover: Arc<dyn ProofProver>,
    hasher: Arc<dyn NoteHasher>,
) -> AppDeps {
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
        ledger: Arc::new(InProcessLedger::new(pool.clone())),
        prover,
        hasher,
    }
}

/// 桩组件装配（非 shielded 场景）。
fn deps(pool: sqlx::PgPool) -> AppDeps {
    deps_with(&pool, Arc::new(StubProver), Arc::new(StubHasher))
}

/// 真实组件装配（Poseidon + ProverDispatcher，shielded 场景）。
pub fn deps_real(pool: sqlx::PgPool) -> AppDeps {
    deps_with(
        &pool,
        Arc::new(ProverDispatcher),
        Arc::new(PoseidonNoteHasher),
    )
}

fn engine_with(deps: AppDeps) -> IntentEngine {
    let mut map = vg_application::HandlerMap::new();
    vg_application::register_default(&mut map);
    IntentEngine::new(deps, map)
}

pub fn engine(pool: sqlx::PgPool) -> IntentEngine {
    engine_with(deps(pool))
}

pub fn engine_real(pool: sqlx::PgPool) -> IntentEngine {
    engine_with(deps_real(pool))
}

// ---- 身份 / 商品 / 策略 / 凭证 fixture ----

pub fn did(s: &str) -> Did {
    Did::parse(s).unwrap()
}

fn doc(d: Did, kind: SubjectKind) -> DidDocument {
    DidDocument {
        did: d.clone(),
        kind,
        methods: vec![VerificationMethod::new(
            "k-0",
            KeyType::Secp256k1,
            Hash32::keccak(b"pk"),
            d,
        )],
        parent: None,
        jurisdiction: Some("CN".into()),
        created_at: Utc::now(),
    }
}

/// 建主体（辖区 CN）+ 能力授予；grantor 一并建档。
pub async fn seed_party(
    pool: &sqlx::PgPool,
    subject: &Did,
    kind: SubjectKind,
    caps: &[vg_domain::identity::capability::Action],
) {
    let mut tx = pool.begin().await.unwrap();
    let identity = PgIdentityRepo;
    identity
        .save_document(&mut tx, &doc(subject.clone(), kind))
        .await
        .unwrap();
    let grantor = did("did:vg:user:grantor-e2e");
    identity
        .save_document(&mut tx, &doc(grantor.clone(), SubjectKind::Regulator))
        .await
        .unwrap();
    for cap in caps {
        identity
            .grant_capability(
                &mut tx,
                &Capability::new(subject.clone(), *cap, grantor.clone(), None).unwrap(),
            )
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
}

/// 商品档案（category 为策略 product_type 匹配键）。
pub async fn seed_product(pool: &sqlx::PgPool, id: &str, category: &str) {
    let mut tx = pool.begin().await.unwrap();
    PgCommodityRepo
        .save_product(
            &mut tx,
            &vg_domain::commodity::ProductType::new(
                ProductId::new(id),
                category,
                Hash32::keccak(b"e2e-meta"),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// 策略落库（供场景自组 Policy 后调用）。
pub async fn save_policy(tx: &mut PgTx, policy: &Policy) {
    PgPolicyRepository.save_policy(tx, policy).await.unwrap();
}

/// 监管域落库。
pub async fn save_domain(tx: &mut PgTx, domain: &RegulatoryDomain) {
    PgPolicyRepository.save_domain(tx, domain).await.unwrap();
}

/// 给主体签发 VC（fixture 直写，不经 handler——不产生锚/审计）。
pub async fn seed_vc(pool: &sqlx::PgPool, ctype: CredentialType, subject: &Did) {
    let mut tx = pool.begin().await.unwrap();
    PgCredentialRepo
        .save(
            &mut tx,
            &VerifiableCredential::new(
                vg_domain::shared::CredentialId::generate(),
                did("did:vg:user:issuer-e2e"),
                subject.clone(),
                ctype,
                serde_json::json!({"scope": "e2e-fixture"}),
                Utc::now() - chrono::Duration::days(1),
                Some(Utc::now() + chrono::Duration::days(365)),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// 建批（初始 Created）+ 所有权档案（owner=subject）。
pub async fn seed_available_batch(
    pool: &sqlx::PgPool,
    batch_id: &str,
    product_id: &str,
    owner: &Did,
) {
    let mut tx = pool.begin().await.unwrap();
    let batch = vg_domain::commodity::Batch::new(
        vg_domain::shared::BatchId::new(batch_id),
        ProductId::new(product_id),
        10,
        "kg",
        Utc::now() - chrono::Duration::days(1),
        owner.clone(),
    )
    .unwrap();
    PgCommodityRepo.save_batch(&mut tx, &batch).await.unwrap();
    PgOwnershipRepo
        .init_owner(
            &mut tx,
            &OwnershipState::initialize(
                SubjectRef::Batch(vg_domain::shared::BatchId::new(batch_id)),
                owner.clone(),
                Utc::now() - chrono::Duration::days(1),
            ),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

// ---- intent 构造 ----

/// nonce 全局单调递增：跨测试进程内不撞 (actor, nonce) 防重放键。
pub fn raw(id: &str, action: IntentAction, actor: &Did, payload: serde_json::Value) -> RawIntent {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NONCE: AtomicU64 = AtomicU64::new(1);
    raw_with_nonce(
        id,
        action,
        actor,
        payload,
        NONCE.fetch_add(1, Ordering::SeqCst),
    )
}

/// 显式 nonce（幂等重放 / 重放拒绝场景用）。
pub fn raw_with_nonce(
    id: &str,
    action: IntentAction,
    actor: &Did,
    payload: serde_json::Value,
    nonce: u64,
) -> RawIntent {
    RawIntent {
        id: IntentId::new(id),
        action,
        actor: actor.clone(),
        on_behalf_of: None,
        payload,
        nonce,
        expires_at: Utc::now() + chrono::Duration::hours(1),
    }
}

// ---- SQL 断言小件 ----

pub async fn ownership_row(pool: &sqlx::PgPool, subject: &str) -> (String, i64, i64) {
    sqlx::query_as(
        "SELECT owner, transfer_count, c2c_count FROM ownership_states WHERE subject = $1",
    )
    .bind(subject)
    .fetch_one(pool)
    .await
    .unwrap()
}

pub async fn batch_active_state(pool: &sqlx::PgPool, id: &str) -> (bool, String) {
    sqlx::query_as("SELECT active, state FROM batches WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

pub async fn lifecycle_chain(
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

pub async fn outbox_types(pool: &sqlx::PgPool, intent_id: &str) -> Vec<String> {
    let rows: Vec<(serde_json::Value,)> =
        sqlx::query_as("SELECT payload FROM domain_events WHERE aggregate = $1 ORDER BY id ASC")
            .bind(format!("intent:{intent_id}"))
            .fetch_all(pool)
            .await
            .unwrap();
    rows.into_iter()
        .map(|(p,)| p["event_type"].as_str().unwrap().to_string())
        .collect()
}

pub async fn audit_policy(pool: &sqlx::PgPool, intent_id: &str) -> (Option<String>, Option<i64>) {
    sqlx::query_as(
        "SELECT policy_id, policy_version FROM audit_events \
         WHERE intent_id = $1 AND result = 'allow'",
    )
    .bind(intent_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

pub async fn cred_status(pool: &sqlx::PgPool, id: &str) -> String {
    let (s,): (String,) = sqlx::query_as("SELECT status FROM credentials WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
    s
}

pub async fn anchor_count(pool: &sqlx::PgPool, kind: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM ledger_anchors WHERE kind = $1")
        .bind(kind)
        .fetch_one(pool)
        .await
        .unwrap();
    n
}

/// 幂等场景的全表快照（重放前后逐字段比对）。
#[derive(Debug, PartialEq, Eq)]
pub struct Counts {
    pub intents: i64,
    pub transfers: i64,
    pub lifecycle_events: i64,
    pub domain_events: i64,
    pub audit_events: i64,
    pub ledger_anchors: i64,
}

pub async fn table_counts(pool: &sqlx::PgPool) -> Counts {
    async fn one(pool: &sqlx::PgPool, table: &str) -> i64 {
        let (n,): (i64,) = sqlx::query_as(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(pool)
            .await
            .unwrap();
        n
    }
    Counts {
        intents: one(pool, "intents").await,
        transfers: one(pool, "transfers").await,
        lifecycle_events: one(pool, "lifecycle_events").await,
        domain_events: one(pool, "domain_events").await,
        audit_events: one(pool, "audit_events").await,
        ledger_anchors: one(pool, "ledger_anchors").await,
    }
}

// ---- shielded fixture（移植自 handlers/shielded.rs 测试段） ----

pub struct ShieldedParties {
    pub sender_did: Did,
    pub recipient_did: Did,
    pub regulator_did: Did,
    pub recipient_meta: vg_domain::privacy::StealthMetaAddress,
    pub view_priv_hex: String,
    pub spend_pub_hex: String,
    pub reg_view_priv_hex: String,
    pub reg_view_pub_hex: String,
}

/// 三方密钥 fixture：发送方 / 接收方（view+spend）/ 监管（view）。
pub async fn seed_shielded_parties(pool: &sqlx::PgPool) -> ShieldedParties {
    let sender_kp = KeyPair::generate();
    let sender_did = did(&vg_infra_crypto::pubkey_to_did(sender_kp.public()));
    let recipient_did = did("did:vg:user:retailer-e2e-shield");
    let regulator_did = did("did:vg:user:reg-e2e-shield");

    let view_kp = KeyPair::generate();
    let spend_kp = KeyPair::generate();
    let reg_kp = KeyPair::generate();
    let meta_view =
        vg_infra_crypto::StealthMetaAddressView::from_keys(view_kp.public(), spend_kp.public());

    let mut tx = pool.begin().await.unwrap();
    let identity = PgIdentityRepo;
    for (d, kind) in [
        (&sender_did, SubjectKind::Enterprise),
        (&recipient_did, SubjectKind::Enterprise),
        (&regulator_did, SubjectKind::Regulator),
    ] {
        identity
            .save_document(&mut tx, &doc(d.clone(), kind))
            .await
            .unwrap();
    }
    let grantor = did("did:vg:user:grantor-e2e");
    identity
        .save_document(&mut tx, &doc(grantor.clone(), SubjectKind::Regulator))
        .await
        .unwrap();
    identity
        .grant_capability(
            &mut tx,
            &Capability::new(
                sender_did.clone(),
                vg_domain::identity::capability::Action::SubmitShieldedTx,
                grantor,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();

    ShieldedParties {
        sender_did,
        recipient_did,
        regulator_did,
        recipient_meta: meta_view,
        view_priv_hex: hex::encode(view_kp.secret().to_bytes()),
        spend_pub_hex: spend_kp.public_compressed().as_hex(),
        reg_view_priv_hex: hex::encode(reg_kp.secret().to_bytes()),
        reg_view_pub_hex: reg_kp.public_compressed().as_hex(),
    }
}

pub struct OldNoteSpec {
    pub secret: String,
    pub salt: String,
    pub owner_ot_addr: Hash32,
    pub amount: u64,
}

/// 旧 Note 裸 SQL seed（发送方自持有；移植自 shielded 测试）。
pub async fn seed_old_note(pool: &sqlx::PgPool, subject: &SubjectRef, amount: u64) -> OldNoteSpec {
    let mut secret = vg_infra_crypto::generate_note_secret();
    secret[0] |= 0x80;
    let salt = vg_infra_crypto::generate_note_salt();
    let owner = Hash32::keccak(b"e2e-old-owner");
    let note = vg_domain::privacy::Note::new(subject.clone(), owner, amount, secret, salt).unwrap();
    let commitment = note.commitment(&PoseidonNoteHasher);
    let filler = KeyPair::generate().public_compressed();
    sqlx::query(
        "INSERT INTO notes (commitment, asset_ref, owner_ot_addr, amount, created_tx, \
             addr_point, ephemeral, secret, salt) \
         VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, $8)",
    )
    .bind(commitment.as_bytes().as_slice())
    .bind(subject_label(subject))
    .bind(owner.as_bytes().as_slice())
    .bind(amount as i64)
    .bind(filler.as_bytes().as_slice())
    .bind(filler.as_bytes().as_slice())
    .bind(secret.as_slice())
    .bind(salt.as_slice())
    .execute(pool)
    .await
    .unwrap();
    OldNoteSpec {
        secret: hex::encode(secret),
        salt: hex::encode(salt),
        owner_ot_addr: owner,
        amount,
    }
}

fn subject_label(subject: &SubjectRef) -> String {
    match subject {
        SubjectRef::Batch(id) => format!("batch:{id}"),
        SubjectRef::Asset(id) => format!("asset:{id}"),
    }
}

pub fn shielded_payload(
    p: &ShieldedParties,
    subject: &SubjectRef,
    old: &OldNoteSpec,
) -> serde_json::Value {
    let subject_id = match subject {
        SubjectRef::Batch(id) => id.to_string(),
        SubjectRef::Asset(id) => id.to_string(),
    };
    serde_json::json!({
        "subject": {"type": "batch", "id": subject_id},
        "old_note": {
            "secret": old.secret, "salt": old.salt,
            "owner_ot_addr": old.owner_ot_addr.as_hex(), "amount": old.amount
        },
        "recipient_meta": {
            "view_pub": p.recipient_meta.view_pub.as_hex(),
            "spend_pub": p.recipient_meta.spend_pub.as_hex()
        },
        "amount": old.amount,
        "from_did": p.sender_did.as_str(),
        "to_did": p.recipient_did.as_str(),
        "regulator_view_pub": p.reg_view_pub_hex
    })
}

pub fn raw_shielded(id: &str, actor: &Did, payload: serde_json::Value, nonce: u64) -> RawIntent {
    raw_with_nonce(id, IntentAction::ShieldedTransfer, actor, payload, nonce)
}

pub use vg_domain::identity::SubjectKind;
