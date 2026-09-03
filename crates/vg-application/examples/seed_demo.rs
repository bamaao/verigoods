//! seed_demo：向数据库注入一套可复用的演示数据（可重跑，幂等跳过）。
//!
//! 运行：`cargo run -p vg-application --example seed_demo`
//! （需 PostgreSQL 已启动且 `.env` / `DATABASE_URL` 指向目标库；
//! 缺省回退 `postgres://postgres@localhost:5432/verigoods`。）
//!
//! 产出物：
//! - 监管域 `vg:domain:demo-cn-food` + 2 条 CN/food 策略
//!   （生产许可：Created→Produced；食品安全：Produced→Available
//!   与召回恢复 Recalled→Available）；
//! - 3 个 DID（固定私钥，便于演示文档引用）：
//!   企业（批次/保管能力）、检测机构（签发凭证）、监管者（策略注册）；
//! - 产品 `prod-demo-milk` + 批次 `batch-demo-001`（Available，100 箱）；
//! - 1 张 FoodSafetyInspection VC（签发者为检测机构）。
//!
//! 最后用企业私钥现场签名一条 `GET /api/v1/products/prod-demo-milk`
//! 的 VG-SIG 头并打印——可复制体验鉴权链路（ts/nonce 时效 ±300s，
//! 演示头 5 分钟内有效，且 nonce 一次性）。

use chrono::{Duration, Utc};
use k256::SecretKey;
use vg_domain::commodity::ports::CommodityRepository;
use vg_domain::commodity::{Batch, ProductType};
use vg_domain::credential::ports::CredentialRepository;
use vg_domain::credential::{CredentialSchema, CredentialType, VerifiableCredential};
use vg_domain::identity::capability::Action;
use vg_domain::identity::ports::IdentityRepository;
use vg_domain::identity::{Capability, DidDocument, KeyType, SubjectKind, VerificationMethod};
use vg_domain::lifecycle::LifecycleState;
use vg_domain::ownership::ports::OwnershipRepository;
use vg_domain::ownership::OwnershipState;
use vg_domain::policy::ports::PolicyRepository;
use vg_domain::policy::{Policy, RegulatoryDomain};
use vg_domain::shared::{BatchId, CredentialId, Did, Hash32, ProductId, SubjectRef};
use vg_infra_crypto::{pubkey_to_did, KeyPair};
use vg_infra_pg::{
    PgCommodityRepo, PgCredentialRepo, PgIdentityRepo, PgOwnershipRepo, PgPolicyRepository,
};

// ---- 固定演示私钥（32 字节 hex；仅演示用，严禁用于生产） ----

/// 企业主体私钥。
const ENT_SECRET: &str = "0101010101010101010101010101010101010101010101010101010101010101";
/// 检测机构私钥。
const LAB_SECRET: &str = "0202020202020202020202020202020202020202020202020202020202020202";
/// 监管者私钥（同时是演示数据的授权 grantor）。
const REG_SECRET: &str = "0303030303030303030303030303030303030303030303030303030303030303";

const PRODUCT_ID: &str = "prod-demo-milk";
const BATCH_ID: &str = "batch-demo-001";
const VC_ID: &str = "cred-demo-foodsafety-001";

fn kp(hex_secret: &str) -> KeyPair {
    let bytes = hex::decode(hex_secret).expect("演示私钥 hex 非法");
    let sk = SecretKey::from_slice(&bytes).expect("演示私钥不是合法 secp256k1 标量");
    KeyPair::from_secret(sk)
}

/// 判定某表某 id 是否已存在（幂等跳过依据）。
async fn exists(pool: &sqlx::PgPool, table: &str, id: &str) -> bool {
    let sql = format!("SELECT 1 FROM {table} WHERE id = $1");
    let hit: Option<i32> = sqlx::query_scalar(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("幂等存在性查询失败");
    hit.is_some()
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres@localhost:5432/verigoods".into());
    let pool = vg_infra_pg::pool::connect(&url)
        .await
        .unwrap_or_else(|e| panic!("数据库连接失败（{url}）：{e}"));
    vg_infra_pg::migrate(&pool)
        .await
        .unwrap_or_else(|e| panic!("数据库迁移失败：{e}"));
    println!("已连接并应用迁移：{url}");

    // ---- 固定密钥三方 ----
    let ent = kp(ENT_SECRET);
    let lab = kp(LAB_SECRET);
    let reg = kp(REG_SECRET);
    let ent_did = Did::parse(&pubkey_to_did(ent.public())).unwrap();
    let lab_did = Did::parse(&pubkey_to_did(lab.public())).unwrap();
    let reg_did = Did::parse(&pubkey_to_did(reg.public())).unwrap();

    let already = exists(&pool, "dids", ent_did.as_str()).await;

    if !already {
        seed_all(&pool, &ent, &lab, &reg, &ent_did, &lab_did, &reg_did).await;
    } else {
        println!("演示数据已存在，跳过写入（幂等重跑）");
    }

    // ---- 摘要输出 ----
    println!("\n========== 演示数据摘要 ==========");
    println!(
        "企业      DID: {} （私钥 0x{ENT_SECRET}）",
        ent_did.as_str()
    );
    println!(
        "检测机构  DID: {} （私钥 0x{LAB_SECRET}）",
        lab_did.as_str()
    );
    println!(
        "监管者    DID: {} （私钥 0x{REG_SECRET}）",
        reg_did.as_str()
    );
    println!("监管域    : vg:domain:demo-cn-food（CN/food）");
    println!("策略      : pol-demo-production v1（Created→Produced 需 ProductionLicense）");
    println!(
        "策略      : pol-demo-foodsafety v1（→Available 需 FoodSafetyInspection，含召回恢复边）"
    );
    println!("产品      : {PRODUCT_ID}");
    println!("批次      : {BATCH_ID}（Available，100 箱，owner=企业）");
    println!("VC        : {VC_ID}（FoodSafetyInspection，issuer=检测机构）");

    // ---- 现场签名一条演示 VG-SIG 头（GET /api/v1/products/{id}） ----
    let ts = Utc::now().timestamp();
    let nonce = format!("seed-demo-{}", ts);
    let method = "GET";
    let path = format!("/api/v1/products/{PRODUCT_ID}");
    let msg = format!("vg:sig:v1\n{method}\n{path}\n{ts}\n{nonce}");
    let (sig, rid) = ent.sign_recoverable(msg.as_bytes()).expect("演示签名失败");
    let mut s65 = [0u8; 65];
    s65[..64].copy_from_slice(&sig.to_bytes());
    s65[64] = 27 + u8::from(rid.is_y_odd());

    println!("\n---------- curl 体验 ----------");
    println!("# 1) 免签健康检查");
    println!("curl -i http://127.0.0.1:8080/health");
    println!("# 2) 免签消费者只读（批次合规视图）");
    println!("curl -i http://127.0.0.1:8080/api/v1/consumer/batch:{BATCH_ID}");
    println!("# 3) 签名请求（VG-SIG 头为上方现场签名，ts/nonce 时效 ±300s 且 nonce 一次性）");
    println!(
        "curl -i -H 'VG-SIG: did=\"{}\", sig=\"0x{}\", ts={ts}, nonce=\"{nonce}\"' \\\n  http://127.0.0.1:8080{path}",
        ent_did.as_str(),
        hex::encode(s65),
    );
}

#[allow(clippy::too_many_arguments)]
async fn seed_all(
    pool: &sqlx::PgPool,
    ent: &KeyPair,
    lab: &KeyPair,
    reg: &KeyPair,
    ent_did: &Did,
    lab_did: &Did,
    reg_did: &Did,
) {
    let now = Utc::now();
    let day_ago = now - Duration::days(1);

    // ---- 身份：监管者先建档（授权 grantor），再企业/检测机构 + 能力 ----
    let identity = PgIdentityRepo;
    let mut tx = pool.begin().await.expect("事务开启失败");

    let doc = |kp: &KeyPair, did: &Did, kind: SubjectKind| DidDocument {
        did: did.clone(),
        kind,
        methods: vec![VerificationMethod::new(
            "k-0",
            KeyType::Secp256k1,
            kp.pubkey_digest(),
            did.clone(),
        )],
        parent: None,
        jurisdiction: Some("CN".into()),
        created_at: day_ago,
    };
    identity
        .save_document(&mut tx, &doc(reg, reg_did, SubjectKind::Regulator))
        .await
        .unwrap();
    identity
        .save_document(&mut tx, &doc(ent, ent_did, SubjectKind::Enterprise))
        .await
        .unwrap();
    identity
        .save_document(&mut tx, &doc(lab, lab_did, SubjectKind::Inspector))
        .await
        .unwrap();
    for (subject, action) in [
        (ent_did, Action::ReadProduct),
        (ent_did, Action::CreateBatch),
        (ent_did, Action::RequestTransfer),
        (ent_did, Action::TransferOwnership),
        (ent_did, Action::UpdateCustody),
        (lab_did, Action::IssueCredential),
        (reg_did, Action::RegisterPolicy),
    ] {
        identity
            .grant_capability(
                &mut tx,
                &Capability::new(subject.clone(), action, reg_did.clone(), None).unwrap(),
            )
            .await
            .unwrap();
    }
    tx.commit().await.expect("身份事务提交失败");

    // ---- 监管域 + 策略 ----
    let mut tx = pool.begin().await.expect("事务开启失败");
    PgPolicyRepository
        .save_domain(
            &mut tx,
            &RegulatoryDomain {
                domain_id: "vg:domain:demo-cn-food".into(),
                authority: reg_did.clone(),
                jurisdiction: "CN".into(),
                product_types: vec!["food".into()],
                credential_schemas: vec![CredentialSchema {
                    id: "vg:schema:demo-food-safety@v1".into(),
                    ctype: CredentialType::FoodSafetyInspection,
                    required_claims: vec!["result".into()],
                }],
                effective_from: day_ago,
            },
        )
        .await
        .unwrap();
    let policy = |id: &str,
                  creds: Vec<CredentialType>,
                  edges: Vec<(LifecycleState, LifecycleState)>| Policy {
        policy_id: vg_domain::shared::PolicyId::new(id),
        version: 1,
        authority: reg_did.clone(),
        jurisdiction: "CN".into(),
        product_type: "food".into(),
        required_credentials: creds,
        required_proofs: vec![],
        transitions: edges,
        effective_at: day_ago,
        expires_at: None,
        active: true,
    };
    PgPolicyRepository
        .save_policy(
            &mut tx,
            &policy(
                "pol-demo-production",
                vec![CredentialType::ProductionLicense],
                vec![(LifecycleState::Created, LifecycleState::Produced)],
            ),
        )
        .await
        .unwrap();
    PgPolicyRepository
        .save_policy(
            &mut tx,
            &policy(
                "pol-demo-foodsafety",
                vec![CredentialType::FoodSafetyInspection],
                vec![
                    (LifecycleState::Produced, LifecycleState::Available),
                    (LifecycleState::Recalled, LifecycleState::Available),
                ],
            ),
        )
        .await
        .unwrap();
    tx.commit().await.expect("策略事务提交失败");

    // ---- 产品 + 批次（Available）+ 所有权 ----
    let mut tx = pool.begin().await.expect("事务开启失败");
    PgCommodityRepo
        .save_product(
            &mut tx,
            &ProductType::new(
                ProductId::new(PRODUCT_ID),
                "food",
                Hash32::keccak(b"demo-product-metadata"),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let mut batch = Batch::new(
        BatchId::new(BATCH_ID),
        ProductId::new(PRODUCT_ID),
        100,
        "箱",
        day_ago,
        ent_did.clone(),
    )
    .unwrap();
    // 演示口径：批次已走完生产/检验流程，直接置为可售（不补生命周期事件）
    batch.state = LifecycleState::Available;
    PgCommodityRepo.save_batch(&mut tx, &batch).await.unwrap();
    PgOwnershipRepo
        .init_owner(
            &mut tx,
            &OwnershipState::initialize(
                SubjectRef::Batch(BatchId::new(BATCH_ID)),
                ent_did.clone(),
                day_ago,
            ),
        )
        .await
        .unwrap();
    tx.commit().await.expect("商品事务提交失败");

    // ---- VC（fixture 直写口径：不经 handler，不产生锚/审计） ----
    let mut tx = pool.begin().await.expect("事务开启失败");
    PgCredentialRepo
        .save(
            &mut tx,
            &VerifiableCredential::new(
                CredentialId::new(VC_ID),
                lab_did.clone(),
                ent_did.clone(),
                CredentialType::FoodSafetyInspection,
                serde_json::json!({"result": "pass", "scope": "demo", "batch": BATCH_ID}),
                day_ago,
                Some(now + Duration::days(365)),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    tx.commit().await.expect("VC 事务提交失败");
}
