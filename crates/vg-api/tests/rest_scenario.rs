//! Task 24 场景集成测试：sqlx::test 真库 + tower oneshot（不起端口），
//! 复用生产 `vg_api::build_router`。
//!
//! 主线场景（plan）：注册 DID（企业 A/B + 监管）→ 建产品/批次 →
//! 签发 VC → 转移 → 消费者免签视图断言（counters / owner_masked /
//! age_days）。辅助：intent 轮询与 shielded payload 脱敏、approve
//! 端点（L3 停门 → 审批 → Confirmed）、策略 POST→GET 往返（含锚定）、
//! compliance GET、decrypt 无授权 403、坏签名 401、consumer 404。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use tower::ServiceExt;
use vg_api::state::{AppState, NonceStore, SharedState};
use vg_application::{AppDeps, HandlerMap, IntentEngine};
use vg_domain::identity::{Capability, DidDocument, KeyType, SubjectKind, VerificationMethod};
use vg_domain::privacy::Note;
use vg_domain::shared::{Did, Hash32, SubjectRef};
use vg_domain::identity::ports::IdentityRepository;
use vg_infra_crypto::KeyPair;
use vg_infra_pg::*;

// ---------- fixture ----------

fn test_state(pool: sqlx::PgPool) -> SharedState {
    let deps = AppDeps {
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
        prover: Arc::new(vg_infra_zk::dispatcher::ProverDispatcher),
        hasher: Arc::new(vg_infra_crypto::PoseidonNoteHasher),
    };
    let mut map = HandlerMap::new();
    vg_application::register_default(&mut map);
    Arc::new(AppState {
        engine: IntentEngine::new(deps, map),
        pool,
        nonce_store: NonceStore::new(),
    })
}

/// 落库一个 DID 主体（可选辖区）并授予动作能力；返回密钥对。
async fn seed_identity(
    pool: &sqlx::PgPool,
    kind: SubjectKind,
    jurisdiction: Option<String>,
    caps: &[vg_domain::identity::Action],
) -> KeyPair {
    let kp = KeyPair::generate();
    let did = Did::parse(&vg_infra_crypto::pubkey_to_did(kp.public())).unwrap();
    let method = VerificationMethod::new(
        "k-0",
        KeyType::Secp256k1,
        kp.pubkey_digest(),
        did.clone(),
    );
    let doc = DidDocument {
        did: did.clone(),
        kind,
        methods: vec![method],
        parent: None,
        jurisdiction,
        created_at: Utc::now(),
    };
    let repo = PgIdentityRepo;
    let mut tx = pool.begin().await.unwrap();
    repo.save_document(&mut tx, &doc).await.unwrap();
    for action in caps {
        // Phase1 口径：任何 actor（含企业）都须持有能力——授权方用主体
        // 自身（非 Agent 即合法）
        let cap = Capability::new(did.clone(), *action, did.clone(), None).unwrap();
        repo.grant_capability(&mut tx, &cap).await.unwrap();
    }
    tx.commit().await.unwrap();
    kp
}

fn did_of(kp: &KeyPair) -> String {
    vg_infra_crypto::pubkey_to_did(kp.public())
}

/// 签名请求助手：nonce 全局递增（同一测试内各请求互不重放）。
struct Signer {
    kp: KeyPair,
    nonce: std::cell::Cell<u64>,
}

impl Signer {
    fn new(kp: KeyPair) -> Self {
        Self {
            kp,
            nonce: std::cell::Cell::new(0),
        }
    }

    fn request(&self, method: &str, path: &str, body: Option<Value>) -> Request<Body> {
        let nonce = self.nonce.get() + 1;
        self.nonce.set(nonce);
        let ts = Utc::now().timestamp();
        let method_obj = Method::from_bytes(method.as_bytes()).unwrap();
        // 签名口径：不含 query 的纯路径；nonce 全局唯一（签名者前缀 + 递增）
        let pure_path = path.split('?').next().unwrap_or(path);
        let nonce_str = format!("{}-{nonce}", &did_of(&self.kp)["did:vg:".len().."did:vg:".len() + 16]);
        let msg = vg_api::middleware::auth::sign_message(&method_obj, pure_path, ts, &nonce_str);
        let (sig, rid) = self.kp.sign_recoverable(msg.as_bytes()).unwrap();
        let mut s65 = [0u8; 65];
        s65[..64].copy_from_slice(&sig.to_bytes());
        s65[64] = 27 + u8::from(rid.is_y_odd());
        let mut builder = Request::builder()
            .method(method_obj)
            .uri(path)
            .header(
                "VG-SIG",
                format!(
                    "did=\"{}\", sig=\"0x{}\", ts={ts}, nonce=\"{nonce_str}\"",
                    did_of(&self.kp),
                    hex::encode(s65)
                ),
            );
        let body = match body {
            Some(v) => {
                builder = builder.header("content-type", "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        builder.body(body).unwrap()
    }
}

async fn send(router: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap_or(Value::Null)
    };
    (status, v)
}

// ---------- 主线场景 ----------

/// 注册 DID → 建产品/批次 → 签发 VC → 转移 → 消费者免签视图。
#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn full_lifecycle_scenario(pool: sqlx::PgPool) {
    use vg_domain::identity::Action;
    let state = test_state(pool.clone());
    let router = vg_api::build_router(state.clone());

    let ent_a = seed_identity(
        &pool,
        SubjectKind::Enterprise,
        Some("cn".into()),
        &[
            Action::CreateBatch,
            Action::TransferOwnership,
            Action::IssueCredential,
        ],
    )
    .await;
    let ent_b = seed_identity(&pool, SubjectKind::Enterprise, Some("cn".into()), &[]).await;
    let a = Signer::new(ent_a.clone());
    let did_a = did_of(&ent_a);
    let did_b = did_of(&ent_b);

    // DID 注册：免签引导端点，首次 201 / 重复 200（全新主体，未落过库）
    let fresh = KeyPair::generate();
    let fresh_did = did_of(&fresh);
    let doc_b = json!({
        "did": fresh_did,
        "kind": "enterprise",
        "methods": [{ "id": "k-0", "key_type": "secp256k1",
                      "public_key": fresh.pubkey_digest().as_hex(),
                      "controller": fresh_did, "revoked": false }],
        "parent": null, "jurisdiction": "cn",
        "created_at": Utc::now().to_rfc3339(),
    });
    let (s, _) = send(
        &router,
        Signer::request(
            &Signer::new(KeyPair::generate()), // 免签：签名头不被校验
            "POST",
            "/api/v1/dids",
            Some(doc_b.clone()),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "首次 DID 注册应 201");
    let (s, _) = send(
        &router,
        Signer::request(&Signer::new(KeyPair::generate()), "POST", "/api/v1/dids", Some(doc_b)),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "重复注册应 upsert 200");

    // GET /dids/{did}（需签）
    let (s, v) = send(
        &router,
        a.request("GET", &format!("/api/v1/dids/{did_a}"), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "DID 查询应 200：{v}");
    assert_eq!(v["did"].as_str().unwrap(), did_a);

    // 产品建档（需签）→ 201
    let (s, v) = send(
        &router,
        a.request(
            "POST",
            "/api/v1/products",
            Some(json!({"product_id": "pd-milk", "category": "milk",
                        "metadata_hash": "11".repeat(32)})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "产品建档应 201：{v}");
    // GET /products/{id}
    let (s, _) = send(
        &router,
        a.request("GET", "/api/v1/products/pd-milk", None),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send(
        &router,
        a.request("GET", "/api/v1/products/none", None),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // 建批次（Created，无 target_state）→ Confirmed
    let (s, v) = send(
        &router,
        a.request(
            "POST",
            "/api/v1/batches",
            Some(json!({
                "subject": {"type": "batch", "id": "bt-001"},
                "product_id": "pd-milk", "quantity": 100, "unit": "kg"
            })),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "建批次应 200：{v}");
    assert_eq!(v["status"], "confirmed", "L2 无审批门应直达 Confirmed：{v}");
    let _create_intent = v["intent_id"].as_str().unwrap().to_owned();

    // 幂等重试：同 intent_id 二次提交返回同一结果
    let (s2, v2) = send(
        &router,
        a.request(
            "POST",
            "/api/v1/batches",
            Some(json!({
                "intent_id": _create_intent,
                "subject": {"type": "batch", "id": "bt-001"},
                "product_id": "pd-milk", "quantity": 100, "unit": "kg"
            })),
        ),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(v2["intent_id"], v["intent_id"], "幂等键重试应返回同一意图");

    // 签发 VC（写走 intent）
    let (s, v) = send(
        &router,
        a.request(
            "POST",
            "/api/v1/credentials",
            Some(json!({
                "subject": {"type": "batch", "id": "bt-001"},
                "holder": did_a, "ctype": "food_safety_inspection",
                "claims": {"result": "passed"}
            })),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "签发 VC 应 200：{v}");
    assert_eq!(v["status"], "confirmed", "签发应直达 Confirmed：{v}");

    // GET /credentials?subject（含 claims 与 credential_hash hex）
    let (s, v) = send(
        &router,
        a.request("GET", &format!("/api/v1/credentials?subject={did_a}"), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "凭证列表应 200：{v}");
    let arr = v.as_array().expect("凭证列表应为数组");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["claims"]["result"], "passed");
    assert_eq!(arr[0]["credential_hash"].as_str().unwrap().len(), 64);

    // 转移 A → B（c2c）
    let (s, v) = send(
        &router,
        a.request(
            "POST",
            "/api/v1/transfers",
            Some(json!({
                "subject": {"type": "batch", "id": "bt-001"},
                "to": did_b, "c2c": true
            })),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "转移应 200：{v}");
    assert_eq!(v["status"], "confirmed", "公开转移 L3 无停门（仅 shielded 有），应 Confirmed：{v}");
    let transfer_intent = v["intent_id"].as_str().unwrap().to_owned();

    // GET /transfers?subject=batch:bt-001（query 字符串口径）
    let (s, v) = send(
        &router,
        a.request("GET", "/api/v1/transfers?subject=batch:bt-001", None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "转移历史应 200：{v}");
    let records = v.as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["c2c"], true);
    assert_eq!(records[0]["to"].as_str().unwrap(), did_b);

    // 批次聚合视图（owner 换手 + counters）
    let (s, v) = send(
        &router,
        a.request("GET", "/api/v1/batches/bt-001", None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "批次聚合应 200：{v}");
    assert_eq!(v["owner"].as_str().unwrap(), did_b, "所有权应已转移给 B");
    assert_eq!(v["transfer_count"], 1);
    assert_eq!(v["c2c_count"], 1);
    assert_eq!(v["state"], "created");

    // intent 轮询：Confirmed 后 result_ref 非空
    let (s, v) = send(
        &router,
        a.request("GET", &format!("/api/v1/intents/{transfer_intent}"), None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "intent 详情应 200：{v}");
    assert_eq!(v["status"], "confirmed");
    assert!(v["result_ref"].is_string(), "Confirmed 后 result_ref 应非空：{v}");
    assert!(v["payload"]["old_note"].is_null(), "非 shielded intent 不做脱敏");

    // compliance GET：无策略 → 无缺失 → compliant
    let (s, v) = send(
        &router,
        a.request("GET", "/api/v1/compliance/batch:bt-001", None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "合规检查应 200：{v}");
    assert_eq!(v["compliant"], true, "无生效策略应合规：{v}");
    // required 查询
    let (s, v) = send(
        &router,
        a.request("GET", "/api/v1/compliance/batch:bt-001/required", None),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.as_array().unwrap().len(), 0);

    // 消费者免签视图（不发 VG-SIG 头）
    let (s, v) = send(
        &router,
        Request::builder()
            .uri("/api/v1/consumer/batch:bt-001")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "消费者视图免签应 200：{v}");
    assert_eq!(v["state"], "created");
    assert_eq!(v["transfer_count"], 1, "转移计数应为 1：{v}");
    assert_eq!(v["c2c_count"], 1);
    let masked = v["owner_masked"].as_str().unwrap();
    assert!(masked.starts_with("DID-"), "掩码应以 DID- 开头：{masked}");
    assert_ne!(masked, did_b, "不得透出完整 owner DID");
    assert!(masked.len() >= 9, "掩码应含 8 位前缀：{masked}");
    assert!(
        did_b.contains(&masked["DID-".len()..].to_lowercase()),
        "掩码前缀应取自 owner DID 后缀：{masked} vs {did_b}"
    );
    assert!(v["age_days"].is_i64(), "age_days 应为数值字段：{v}");
    assert!(v["produced_at"].is_string());
    assert!(v["compliance_ok"].is_boolean());

    // 消费者视图 404：未知批次
    let (s, _) = send(
        &router,
        Request::builder()
            .uri("/api/v1/consumer/batch:nope")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

// ---------- 辅助：坏签名 401（防回归） ----------

#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn unsigned_write_is_401(pool: sqlx::PgPool) {
    let state = test_state(pool);
    let router = vg_api::build_router(state);
    let (s, v) = send(
        &router,
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/transfers")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"subject":{"type":"batch","id":"x"},"to":"did:vg:b","c2c":false}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "无签名写应 401：{v}");
}

// ---------- 辅助：decrypt 无授权 403 ----------

#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn decrypt_without_grant_is_403(pool: sqlx::PgPool) {
    let state = test_state(pool.clone());
    let router = vg_api::build_router(state);
    let regulator = seed_identity(&pool, SubjectKind::Regulator, None, &[]).await;
    let r = Signer::new(regulator);
    let (s, v) = send(
        &router,
        r.request(
            "POST",
            "/api/v1/shielded/decrypt",
            Some(json!({"extra_base64": "AAAA", "view_priv": "00".repeat(32)})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "无数据访问授权应 403：{v}");
    assert_eq!(v["code"], "policy_violated");
}

// ---------- 辅助：策略 POST→GET 往返（含账本锚定） ----------

#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn policy_roundtrip_and_anchor(pool: sqlx::PgPool) {
    let state = test_state(pool.clone());
    let router = vg_api::build_router(state);
    let reg = seed_identity(&pool, SubjectKind::Regulator, None, &[]).await;
    let did_r = did_of(&reg);
    let r = Signer::new(reg);

    let body = json!({
        "policy_id": "pol-cn-milk",
        "version": 1,
        "authority": did_r,
        "jurisdiction": "cn",
        "product_type": "milk",
        "required_credentials": ["food_safety_inspection"],
        "required_proofs": [],
        "transitions": [["created", "produced"]],
        "effective_at": (Utc::now() - Duration::hours(1)).to_rfc3339(),
        "expires_at": null,
        "active": true
    });
    let (s, v) = send(
        &router,
        r.request("POST", "/api/v1/policies", Some(body)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "策略注册应 201：{v}");

    // 候选查询（辖区 + 类目）
    let (s, v) = send(
        &router,
        r.request("GET", "/api/v1/policies?jurisdiction=cn&product_type=milk", None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "策略列表应 200：{v}");
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["policy_id"], "pol-cn-milk");
    assert_eq!(arr[0]["required_credentials"][0], "food_safety_inspection");
    assert_eq!(arr[0]["transitions"][0][0], "created");

    // (id, version) 精确查询 + 404
    let (s, v) = send(
        &router,
        r.request("GET", "/api/v1/policies/pol-cn-milk/1", None),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "策略精确查询应 200：{v}");
    assert_eq!(v["version"], 1);
    let (s, _) = send(
        &router,
        r.request("GET", "/api/v1/policies/pol-cn-milk/9", None),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // 账本锚定断言：policy_registered 分录已落 ledger_anchors
    let anchored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ledger_anchors WHERE kind = 'policy_registered'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(anchored, 1, "策略注册应锚定一条 policy_registered 分录");
}

// ---------- 辅助：Shielded L3 停门 → approve → Confirmed + payload 脱敏 ----------

#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn shielded_transfer_gate_approve_and_intent_sanitization(pool: sqlx::PgPool) {
    use vg_domain::identity::Action;
    let state = test_state(pool.clone());
    let router = vg_api::build_router(state);

    let sender = seed_identity(
        &pool,
        SubjectKind::Enterprise,
        None,
        &[Action::SubmitShieldedTx],
    )
    .await;
    let regulator = seed_identity(&pool, SubjectKind::Regulator, None, &[]).await;
    let recipient = KeyPair::generate(); // 接收方 meta（view/spend 公钥对）
    let s = Signer::new(sender.clone());
    let r = Signer::new(regulator.clone());
    let did_s = did_of(&sender);

    // 构造旧 Note 并落 notes 表（明文列按 0007 迁移口径全量填充）
    let secret = vg_infra_crypto::generate_note_secret();
    let salt = vg_infra_crypto::generate_note_salt();
    let ot_addr = Hash32::from_bytes(vg_infra_crypto::keccak256(b"ot-addr"));
    let subject = SubjectRef::Batch(vg_domain::shared::BatchId::new("bt-shield"));
    let note = Note::new(subject.clone(), ot_addr, 7, secret, salt).unwrap();
    let commitment = note.commitment(&vg_infra_crypto::PoseidonNoteHasher as &dyn vg_domain::ports::NoteHasher);
    sqlx::query(
        "INSERT INTO notes (commitment, asset_ref, owner_ot_addr, amount, addr_point, \
         ephemeral, secret, salt) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(commitment.as_bytes().as_slice())
    .bind("batch:bt-shield")
    .bind(ot_addr.as_bytes().as_slice())
    .bind(7i64)
    .bind([0x02u8; 33].as_slice())
    .bind([0x03u8; 33].as_slice())
    .bind(secret.as_slice())
    .bind(salt.as_slice())
    .execute(&pool)
    .await
    .unwrap();

    let body = json!({
        "subject": {"type": "batch", "id": "bt-shield"},
        "old_note": {
            "secret": hex::encode(secret),
            "salt": hex::encode(salt),
            "owner_ot_addr": ot_addr.as_hex(),
            "amount": 7
        },
        "recipient_meta": {
            "view_pub": hex::encode(recipient.public_compressed().as_bytes()),
            "spend_pub": hex::encode(recipient.public_compressed().as_bytes())
        },
        "amount": 7,
        "from_did": did_s,
        "to_did": "did:vg:user:retailer-x",
        "regulator_view_pub": hex::encode(regulator.public_compressed().as_bytes())
    });

    // execute：L3 停门
    let (status, v) = send(
        &router,
        s.request("POST", "/api/v1/shielded/transfers", Some(body)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "shielded execute 应 200：{v}");
    assert_eq!(v["awaiting_approval"], true, "L3 首跑应停审批门：{v}");
    let intent_id = v["intent_id"].as_str().unwrap().to_owned();

    // intent 详情：shielded payload 的花费密钥被擦除（MEMORY 待办）
    let (status, v) = send(
        &router,
        s.request("GET", &format!("/api/v1/intents/{intent_id}"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let old_note = &v["payload"]["old_note"];
    assert!(old_note.get("secret").is_none(), "secret 必须被擦除：{old_note}");
    assert!(old_note.get("salt").is_none(), "salt 必须被擦除：{old_note}");
    assert_eq!(old_note["amount"], 7, "非敏感字段保留");

    // 未知 intent 404
    let (status, _) = send(
        &router,
        s.request("GET", "/api/v1/intents/it-none", None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // approve（body 可空）：监管方签名 → 续跑 → Confirmed
    let (status, v) = send(
        &router,
        r.request("POST", &format!("/api/v1/intents/{intent_id}/approve"), Some(json!({}))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve 应 200：{v}");
    assert_eq!(v["status"], "confirmed", "审批后续跑应 Confirmed：{v}");
    assert!(v["result_ref"].is_string());

    // 双花：同一旧 Note 二次转移 → intent Rejected（凭空铸造/双花防线）
    let mut body2 = json!({
        "subject": {"type": "batch", "id": "bt-shield"},
        "old_note": {
            "secret": hex::encode(secret),
            "salt": hex::encode(salt),
            "owner_ot_addr": ot_addr.as_hex(),
            "amount": 7
        },
        "recipient_meta": {
            "view_pub": hex::encode(recipient.public_compressed().as_bytes()),
            "spend_pub": hex::encode(recipient.public_compressed().as_bytes())
        },
        "amount": 7,
        "from_did": did_s,
        "to_did": "did:vg:user:retailer-x",
        "regulator_view_pub": hex::encode(regulator.public_compressed().as_bytes())
    });
    body2.as_object_mut().unwrap().remove("intent_id");
    let (status, v) = send(
        &router,
        s.request("POST", "/api/v1/shielded/transfers", Some(body2)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "rejected", "nullifier 已花费应 Rejected：{v}");
}

// ---------- 辅助：validium 根提交 + 授权 → 解密放行 ----------

#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn validium_root_and_grant_then_decrypt_key_error(pool: sqlx::PgPool) {
    let state = test_state(pool.clone());
    let router = vg_api::build_router(state);
    let admin = seed_identity(&pool, SubjectKind::Regulator, None, &[]).await;
    let regulator = seed_identity(&pool, SubjectKind::Regulator, None, &[]).await;
    let a = Signer::new(admin);
    let r = Signer::new(regulator.clone());
    let did_r = did_of(&regulator);

    // 根提交（两条目）
    let (s, v) = send(
        &router,
        a.request(
            "POST",
            "/api/v1/validium/roots",
            Some(json!({"batch_ref": "vb-1", "items": ["11".repeat(32), "22".repeat(32)]})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "根提交应 200：{v}");
    assert_eq!(v["root"].as_str().unwrap().len(), 64);
    // 幂等重放：同 batch_ref 返回同一根
    let (_, v2) = send(
        &router,
        a.request(
            "POST",
            "/api/v1/validium/roots",
            Some(json!({"batch_ref": "vb-1", "items": ["33".repeat(32)]})),
        ),
    )
    .await;
    assert_eq!(v2["root"], v["root"], "同 batch_ref 幂等应返回既有根");

    // 授权 → 解密过第二因子（进入密码学层后因坏私钥 400，证明授权闸门放行）
    let until = (Utc::now() + Duration::hours(1)).to_rfc3339();
    let (s, _) = send(
        &router,
        a.request(
            "POST",
            "/api/v1/validium/grants",
            Some(json!({"grantee": did_r, "dataset": "shielded:extra", "until": until})),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "授权应 200");

    let (s, v) = send(
        &router,
        r.request(
            "POST",
            "/api/v1/shielded/decrypt",
            Some(json!({"extra_base64": "AAAA", "view_priv": "00".repeat(32)})),
        ),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "有授权应过 403 闸门，坏密文/私钥报 400：{v}"
    );
    assert_eq!(v["code"], "invalid_input");
}
