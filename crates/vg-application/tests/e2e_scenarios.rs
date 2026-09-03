//! Task 28 端到端场景测试（黑盒级：engine.execute / services + SQL 断言）。
//!
//! 五大场景（plan 必测，每场景独立 `sqlx::test` 库隔离）：
//! 1. `pork_full_chain`：监管域+策略注册 → 企业/检测机构 DID → 生产批次
//!    → FoodSafety VC → 拆分两子批 → 子批 1 三次转移 → 消费者视图
//!    （transfer_count=3、c2c_count=0）；
//! 2. `crab_c2c`：单品两跳 c2c 转移（Owned→Resold 状态链，c2c_count=2）；
//! 3. `shielded_flow`：隐匿转移全链（审批门→三表→扫描→监管解密）；
//! 4. `recall_cascade`：撤销 VC → RECALLED → 重签发 → 恢复 Available；
//! 5. `idempotent_intent`：同 intentId 重放零副作用；同 nonce 异 id →
//!    ReplayDetected。
//!
//! fixture 模块内建（集成测试无法借用库内 `#[cfg(test)]` 私有 helper，
//! 从 handlers/mod.rs / credential.rs / shielded.rs 测试段移植，可适配）。

mod fixture;

use fixture::*;
use vg_application::AppError;
use vg_domain::intent::{IntentAction, IntentStatus};
use vg_domain::shared::{Did, DomainError, Hash32, IntentId, SubjectRef};

// =====================================================================
// 场景 1：猪肉全链路（监管域 → 生产 → 检测 VC → 拆分 → 三次转移 → 消费者）
// =====================================================================

/// 监管域 + Policy v1（Created→Produced 需 production_license；
/// Produced→Inspected 与 Recalled→Available 恢复边需 food_safety）。
async fn seed_pork_governance(pool: &sqlx::PgPool, regulator: &Did) {
    use vg_domain::credential::CredentialType;
    use vg_domain::lifecycle::LifecycleState;
    use vg_domain::policy::{Policy, RegulatoryDomain};

    let mk = |id: &str,
              version: u64,
              cred: CredentialType,
              edges: Vec<(LifecycleState, LifecycleState)>| Policy {
        policy_id: vg_domain::shared::PolicyId::new(id),
        version,
        authority: regulator.clone(),
        jurisdiction: "CN".into(),
        product_type: "food".into(),
        required_credentials: vec![cred],
        required_proofs: vec![],
        transitions: edges,
        effective_at: chrono::Utc::now() - chrono::Duration::days(1),
        expires_at: None,
        active: true,
    };
    let mut tx = pool.begin().await.unwrap();
    fixture::save_policy(
        &mut tx,
        &mk(
            "pol-e2e-prod",
            1,
            CredentialType::ProductionLicense,
            vec![(LifecycleState::Created, LifecycleState::Produced)],
        ),
    )
    .await;
    fixture::save_policy(
        &mut tx,
        &mk(
            "pol-e2e-food",
            1,
            CredentialType::FoodSafetyInspection,
            vec![
                (LifecycleState::Produced, LifecycleState::Inspected),
                (LifecycleState::Recalled, LifecycleState::Available),
            ],
        ),
    )
    .await;
    fixture::save_domain(
        &mut tx,
        &RegulatoryDomain {
            domain_id: "dom-e2e-cn-food".into(),
            authority: regulator.clone(),
            jurisdiction: "CN".into(),
            product_types: vec!["food".into()],
            credential_schemas: vec![vg_domain::credential::CredentialSchema {
                id: "vg:schema:e2e-food-safety@v1".into(),
                ctype: CredentialType::FoodSafetyInspection,
                required_claims: vec!["result".into()],
            }],
            effective_from: chrono::Utc::now() - chrono::Duration::days(1),
        },
    )
    .await;
    tx.commit().await.unwrap();
}

#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn pork_full_chain(pool: sqlx::PgPool) {
    use vg_domain::credential::CredentialType;
    use vg_domain::identity::capability::Action as Cap;

    let regulator = did("did:vg:user:reg-e2e");
    let enterprise = did("did:vg:user:ent-e2e-farm");
    let inspector = did("did:vg:user:insp-e2e");
    let retailer = did("did:vg:user:retail-e2e");
    let consumer = did("did:vg:user:consumer-e2e");

    // 身份与能力：监管方（签发凭证）、企业（全链动作）、检测机构/零售商（转移）
    seed_party(
        &pool,
        &regulator,
        SubjectKind::Regulator,
        &[Cap::IssueCredential],
    )
    .await;
    seed_party(
        &pool,
        &enterprise,
        SubjectKind::Enterprise,
        &[Cap::CreateBatch, Cap::TransferOwnership, Cap::UpdateCustody],
    )
    .await;
    seed_party(
        &pool,
        &inspector,
        SubjectKind::Inspector,
        &[Cap::TransferOwnership],
    )
    .await;
    seed_party(
        &pool,
        &retailer,
        SubjectKind::Enterprise,
        &[Cap::TransferOwnership],
    )
    .await;

    seed_product(&pool, "pd-e2e-pork", "food").await;
    seed_pork_governance(&pool, &regulator).await;
    // 生产许可（建档→Produced 的策略凭证，fixture 直写）
    seed_vc(&pool, CredentialType::ProductionLicense, &enterprise).await;

    let eng = engine(pool.clone());
    let batch = |id: &str| serde_json::json!({"type": "batch", "id": id});

    // 1) 生产批次：Created→Produced（production_license v1 命中）
    let r = eng
        .execute(raw(
            "pk-1",
            IntentAction::CreateBatch,
            &enterprise,
            serde_json::json!({
                "subject": batch("bt-e2e-pork"), "product_id": "pd-e2e-pork",
                "quantity": 100, "unit": "kg", "target_state": "produced"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, IntentStatus::Confirmed);
    assert_eq!(
        audit_policy(&pool, "pk-1").await,
        (Some("pol-e2e-prod".into()), Some(1))
    );
    assert_eq!(
        batch_active_state(&pool, "bt-e2e-pork").await,
        (true, "produced".into())
    );

    // 2) FoodSafety VC：监管方签发给企业（经 handler——产生 credential 锚）
    let r = eng
        .execute(raw(
            "pk-2",
            IntentAction::IssueCredential,
            &regulator,
            serde_json::json!({
                "subject": batch("bt-e2e-pork"),
                "holder": enterprise.to_string(),
                "ctype": "food_safety_inspection",
                "claims": {"result": "passed", "score": 96},
                "credential_id": "vc-e2e-food-1",
                "domain_id": "dom-e2e-cn-food"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, IntentStatus::Confirmed);
    assert_eq!(r.result_ref.as_deref(), Some("vc-e2e-food-1"));
    assert_eq!(cred_status(&pool, "vc-e2e-food-1").await, "valid");

    // 3) 守恒拆分：60 + 40 = 100，两子批继承 produced
    let r = eng
        .execute(raw(
            "pk-3",
            IntentAction::SplitBatch,
            &enterprise,
            serde_json::json!({
                "subject": batch("bt-e2e-pork"),
                "children": [
                    {"id": "bt-e2e-c1", "quantity": 60},
                    {"id": "bt-e2e-c2", "quantity": 40}
                ]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, IntentStatus::Confirmed);
    assert_eq!(
        batch_active_state(&pool, "bt-e2e-pork").await,
        (false, "produced".into())
    );
    // 子批不继承迁移态：split 建档停 Created（事件日志与档案同口径）
    assert_eq!(
        batch_active_state(&pool, "bt-e2e-c1").await,
        (true, "created".into())
    );
    assert_eq!(
        batch_active_state(&pool, "bt-e2e-c2").await,
        (true, "created".into())
    );
    let edges: (i64,) =
        sqlx::query_as("SELECT count(*) FROM batch_lineage WHERE parent = 'bt-e2e-pork'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(edges.0, 2);

    // 4) 子批 1 铺 lifecycle 起点：事件日志视角建档即 Created，
    //    保管动作伴随 Created→Produced（再走一次 production_license v1）
    let r = eng
        .execute(raw(
            "pk-4",
            IntentAction::UpdateCustody,
            &enterprise,
            serde_json::json!({
                "subject": batch("bt-e2e-c1"), "to": enterprise.to_string(),
                "reason": "warehouse_in", "lifecycle_to": "produced"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, IntentStatus::Confirmed);
    assert_eq!(
        audit_policy(&pool, "pk-4").await,
        (Some("pol-e2e-prod".into()), Some(1))
    );

    // 5) 子批 1 三次转移：企业→检测（inspected，food_safety v1）
    let r = eng
        .execute(raw(
            "pk-5",
            IntentAction::TransferProduct,
            &enterprise,
            serde_json::json!({
                "subject": batch("bt-e2e-c1"), "to": inspector.to_string(),
                "c2c": false, "lifecycle_to": "inspected"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, IntentStatus::Confirmed);
    assert_eq!(
        audit_policy(&pool, "pk-5").await,
        (Some("pol-e2e-food".into()), Some(1))
    );

    // 6) 检测→零售（available + custody warehouse_in 联动）
    let r = eng
        .execute(raw(
            "pk-6",
            IntentAction::TransferProduct,
            &inspector,
            serde_json::json!({
                "subject": batch("bt-e2e-c1"), "to": retailer.to_string(),
                "c2c": false, "lifecycle_to": "available",
                "custody": {"to": retailer.to_string(), "reason": "warehouse_in"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, IntentStatus::Confirmed);
    let custodian: (String,) =
        sqlx::query_as("SELECT custodian FROM custody_states WHERE subject = 'batch:bt-e2e-c1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(custodian.0, retailer.to_string());

    // 7) 零售→消费者（sold）
    let r = eng
        .execute(raw(
            "pk-7",
            IntentAction::TransferProduct,
            &retailer,
            serde_json::json!({
                "subject": batch("bt-e2e-c1"), "to": consumer.to_string(),
                "c2c": false, "lifecycle_to": "sold"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, IntentStatus::Confirmed);

    // ---- 消费者视图（ownership 口径，REST consumer 视图同源）----
    assert_eq!(
        ownership_row(&pool, "batch:bt-e2e-c1").await,
        (consumer.to_string(), 3, 0),
        "transferCount=3、c2c=0"
    );
    // 子批 2 仍归企业、零计数
    assert_eq!(
        ownership_row(&pool, "batch:bt-e2e-c2").await,
        (enterprise.to_string(), 0, 0)
    );
    assert_eq!(
        batch_active_state(&pool, "bt-e2e-c1").await,
        (true, "sold".into())
    );

    // 生命周期事件链完整（含 policy_version 口径）
    assert_eq!(
        lifecycle_chain(&pool, "batch:bt-e2e-c1").await,
        vec![
            ("created".into(), "produced".into(), Some(1)),
            ("produced".into(), "inspected".into(), Some(1)),
            ("inspected".into(), "available".into(), None),
            ("available".into(), "sold".into(), None),
        ]
    );

    // 转移流水 3 笔（c2c 全 false、计数连续）
    let transfers: Vec<(bool, i64, i64)> = sqlx::query_as(
        "SELECT c2c, transfer_count, c2c_count FROM transfers \
         WHERE subject = 'batch:bt-e2e-c1' ORDER BY serial ASC",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(transfers.len(), 3);
    for (i, (c2c, tc, cc)) in transfers.iter().enumerate() {
        assert!(!c2c);
        assert_eq!((*tc, *cc), ((i + 1) as i64, 0));
    }

    // 审计 allow 分解：1 create + 1 split + 1 issue + 1 custody + 3 transfer = 7
    // （controller 口径"5 条 = 1 create+3 transfer+1 custody"未计 split/issue
    //   两个同为 allow 的 intent，按实际行为断言全量）
    let mut actions: Vec<(String, i64)> = sqlx::query_as(
        "SELECT action, count(*) FROM audit_events WHERE result = 'allow' GROUP BY action",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    actions.sort();
    assert_eq!(
        actions,
        vec![
            ("create_batch".into(), 1),
            ("issue_credential".into(), 1),
            ("split_batch".into(), 1),
            ("transfer_product".into(), 3),
            ("update_custody".into(), 1),
        ]
    );

    // outbox 事件集（8 条）
    let mut evs: Vec<String> =
        sqlx::query_as("SELECT payload->>'event_type' FROM domain_events ORDER BY id ASC")
            .fetch_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|(e,)| e)
            .collect();
    evs.sort();
    assert_eq!(
        evs,
        vec![
            "batch_created".to_string(),
            "batch_split".to_string(),
            "credential_issued".to_string(),
            "custody_changed".to_string(),
            "custody_changed".to_string(),
            "ownership_transferred".to_string(),
            "ownership_transferred".to_string(),
            "ownership_transferred".to_string(),
        ]
    );

    // 账本锚：transfer 3 + credential 1
    assert_eq!(anchor_count(&pool, "transfer").await, 3);
    assert_eq!(anchor_count(&pool, "credential_status").await, 1);
}

// =====================================================================
// 场景 2：单品两跳 c2c（Alice→Bob→Charlie，Owned→Resold）
// =====================================================================

#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn crab_c2c(pool: sqlx::PgPool) {
    use vg_domain::identity::capability::Action as Cap;

    let alice = did("did:vg:user:alice-e2e");
    let bob = did("did:vg:user:bob-e2e");
    let charlie = did("did:vg:user:charlie-e2e");

    seed_party(
        &pool,
        &alice,
        SubjectKind::Consumer,
        &[Cap::CreateBatch, Cap::TransferOwnership, Cap::UpdateCustody],
    )
    .await;
    // Bob 是第二跳的执行方（转移前 owner）：lifecycle 检核需要其辖区，
    // 且 engine 能力段需要 TransferOwnership
    seed_party(
        &pool,
        &bob,
        SubjectKind::Consumer,
        &[Cap::TransferOwnership],
    )
    .await;
    // 类目 seafood：无任何策略 → 生命周期迁移无 policy 版本
    seed_product(&pool, "pd-e2e-crab", "seafood").await;

    let eng = engine(pool.clone());
    let asset = serde_json::json!({"type": "asset", "id": "as-e2e-crab"});

    // 单品建档（owner = Alice，初始 Created）
    let r = eng
        .execute(raw(
            "cb-1",
            IntentAction::CreateItem,
            &alice,
            serde_json::json!({
                "subject": asset, "product_id": "pd-e2e-crab",
                "authenticity_commitment": Hash32::keccak(b"crab-auth").to_string()
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, IntentStatus::Confirmed);
    assert_eq!(
        ownership_row(&pool, "asset:as-e2e-crab").await,
        (alice.to_string(), 0, 0)
    );

    // 保管动作铺路到 Sold（事件日志真相源：created→…→sold 共 4 迁移；
    // 保管人不与现任重复，逐手换占位 DID）
    for (i, to) in [
        "did:vg:user:cust-cb-a",
        "did:vg:user:cust-cb-b",
        "did:vg:user:cust-cb-c",
        "did:vg:user:cust-cb-d",
    ]
    .into_iter()
    .enumerate()
    {
        let lifecycle = ["produced", "inspected", "available", "sold"][i];
        let r = eng
            .execute(raw(
                &format!("cb-l{i}"),
                IntentAction::UpdateCustody,
                &alice,
                serde_json::json!({
                    "subject": asset, "to": to, "reason": "handover", "lifecycle_to": lifecycle
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            r.status,
            IntentStatus::Confirmed,
            "铺路 {lifecycle} 应成功：{:?}",
            r.rejection
        );
    }

    // Alice→Bob（c2c 第一跳，sold→owned）
    let r = eng
        .execute(raw(
            "cb-2",
            IntentAction::TransferProduct,
            &alice,
            serde_json::json!({
                "subject": asset, "to": bob.to_string(), "c2c": true, "lifecycle_to": "owned"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status,
        IntentStatus::Confirmed,
        "c2c 第一跳：{:?}",
        r.rejection
    );
    assert_eq!(
        ownership_row(&pool, "asset:as-e2e-crab").await,
        (bob.to_string(), 1, 1)
    );

    // Bob→Charlie（c2c 第二跳，owned→resold）
    let r = eng
        .execute(raw(
            "cb-3",
            IntentAction::TransferProduct,
            &bob,
            serde_json::json!({
                "subject": asset, "to": charlie.to_string(), "c2c": true, "lifecycle_to": "resold"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status, IntentStatus::Confirmed);

    // 消费者视图：c2c_count=2、终态 Resold
    assert_eq!(
        ownership_row(&pool, "asset:as-e2e-crab").await,
        (charlie.to_string(), 2, 2)
    );
    let (state,): (String,) = sqlx::query_as("SELECT state FROM assets WHERE id = 'as-e2e-crab'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state, "resold");

    // 状态事件链：created→(produced→inspected→available→sold)→owned→resold
    let chain: Vec<(String, String)> = sqlx::query_as(
        "SELECT from_state, to_state FROM lifecycle_events \
         WHERE subject = 'asset:as-e2e-crab' ORDER BY at ASC, id ASC",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let pairs: Vec<(&str, &str)> = chain
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    assert_eq!(
        pairs,
        vec![
            ("created", "produced"),
            ("produced", "inspected"),
            ("inspected", "available"),
            ("available", "sold"),
            ("sold", "owned"),
            ("owned", "resold"),
        ]
    );

    // 转移流水 2 笔、c2c 标记全真
    let transfers: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT from_did, to_did, c2c FROM transfers \
         WHERE subject = 'asset:as-e2e-crab' ORDER BY serial ASC",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(transfers.len(), 2);
    assert_eq!(transfers[0].1, bob.to_string());
    assert_eq!(transfers[1].1, charlie.to_string());
    assert!(transfers.iter().all(|t| t.2));
    assert_eq!(anchor_count(&pool, "transfer").await, 2);
}

// =====================================================================
// 场景 3：隐匿转移全链（真实 crypto + 真实 ZK prove）
// =====================================================================

#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn shielded_flow(pool: sqlx::PgPool) {
    let p = seed_shielded_parties(&pool).await;
    let subject = SubjectRef::Batch(vg_domain::shared::BatchId::new("bt-e2e-shield"));
    let old = seed_old_note(&pool, &subject, 10).await;
    let eng = engine_real(pool.clone());

    // 首跑停 L3 审批门（零业务写入）
    let r1 = eng
        .execute(raw_shielded(
            "sh-1",
            &p.sender_did,
            shielded_payload(&p, &subject, &old),
            1,
        ))
        .await
        .unwrap();
    assert_eq!(r1.status, IntentStatus::PolicyChecked);
    assert!(r1.awaiting_approval);
    let notes: (i64,) = sqlx::query_as("SELECT count(*) FROM notes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(notes.0, 1, "门内不得产生新 Note 行");

    // 审批续跑 → Confirmed
    let r2 = eng
        .approve(&IntentId::new("sh-1"), &p.regulator_did)
        .await
        .unwrap();
    assert_eq!(r2.status, IntentStatus::Confirmed);
    let commitment_hex = r2.result_ref.clone().unwrap();
    assert_eq!(commitment_hex.len(), 64);

    // 三表：notes（新 Note 归接收方 OT 地址）/ nullifiers / shielded_txs
    let note_row: (i64, String) =
        sqlx::query_as("SELECT amount, created_tx FROM notes WHERE commitment = decode($1, 'hex')")
            .bind(&commitment_hex)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(note_row, (10, "sh-1".into()));
    let nf: (i64,) = sqlx::query_as("SELECT count(*) FROM nullifiers WHERE intent_id = 'sh-1'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(nf.0, 1);
    let extra_len: (i32,) = sqlx::query_as(
        "SELECT octet_length(extra) FROM shielded_txs WHERE commitment = decode($1, 'hex')",
    )
    .bind(&commitment_hex)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(extra_len.0 > 0, "ExtraData 密文非空");

    // proofs：note_opening 真实证明且 verified
    let proof: (String, bool) =
        sqlx::query_as("SELECT circuit_id, verified FROM proofs WHERE proof_id = 'pf:sh-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(proof.0, "note_opening");
    assert!(proof.1, "真实 ZK 证明必须验证通过");

    // 账本三件套
    for kind in ["nullifier", "commitment", "encrypted_extra"] {
        assert_eq!(anchor_count(&pool, kind).await, 1, "kind={kind}");
    }

    // 接收方扫描命中恰一张
    let scanned = vg_application::services::shielded::scan_notes(
        &deps_real(pool.clone()),
        &p.view_priv_hex,
        &p.spend_pub_hex,
    )
    .await
    .unwrap();
    assert_eq!(scanned.len(), 1, "接收方扫描应恰命中新 Note");
    assert_eq!(scanned[0].commitment, commitment_hex);
    assert_eq!(scanned[0].amount, 10);
    assert_eq!(scanned[0].asset_ref, "batch:bt-e2e-shield");

    // 第三方视角：明文表/锚定载荷无 from/to DID
    for table in ["notes", "shielded_txs", "ledger_anchors"] {
        let rows: Vec<(String,)> = sqlx::query_as(&format!("SELECT t::text AS s FROM {table} t"))
            .fetch_all(&pool)
            .await
            .unwrap();
        for (text,) in rows {
            assert!(
                !text.contains(p.sender_did.as_str()),
                "{table} 泄漏发送方 DID"
            );
            assert!(
                !text.contains(p.recipient_did.as_str()),
                "{table} 泄漏接收方 DID"
            );
        }
    }

    // 监管解密还原双方 DID
    let extra: (Vec<u8>,) =
        sqlx::query_as("SELECT extra FROM shielded_txs WHERE commitment = decode($1, 'hex')")
            .bind(&commitment_hex)
            .fetch_one(&pool)
            .await
            .unwrap();
    let plain =
        vg_application::services::shielded::regulator_decrypt(&extra.0, &p.reg_view_priv_hex)
            .unwrap();
    assert_eq!(plain["from"], serde_json::json!(p.sender_did.as_str()));
    assert_eq!(plain["to"], serde_json::json!(p.recipient_did.as_str()));
    assert_eq!(plain["asset"], serde_json::json!("batch:bt-e2e-shield"));
    assert!(plain["ts"].is_string());
}

// =====================================================================
// 场景 4：召回级联（撤销 → RECALLED → 重签发 → 恢复）
// =====================================================================

#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn recall_cascade(pool: sqlx::PgPool) {
    use vg_domain::credential::CredentialType;
    use vg_domain::identity::capability::Action as Cap;
    use vg_domain::lifecycle::LifecycleState;
    use vg_domain::policy::Policy;

    let regulator = did("did:vg:user:reg-e2e-rc");
    let enterprise = did("did:vg:user:ent-e2e-rc");
    seed_party(
        &pool,
        &regulator,
        SubjectKind::Regulator,
        &[Cap::IssueCredential, Cap::RevokeCredential],
    )
    .await;
    seed_party(
        &pool,
        &enterprise,
        SubjectKind::Enterprise,
        &[Cap::CreateBatch, Cap::UpdateCustody],
    )
    .await;
    seed_product(&pool, "pd-e2e-rc", "food").await;
    {
        let mut tx = pool.begin().await.unwrap();
        save_policy(
            &mut tx,
            &Policy {
                policy_id: vg_domain::shared::PolicyId::new("pol-e2e-rc"),
                version: 1,
                authority: regulator.clone(),
                jurisdiction: "CN".into(),
                product_type: "food".into(),
                required_credentials: vec![CredentialType::FoodSafetyInspection],
                required_proofs: vec![],
                transitions: vec![(LifecycleState::Recalled, LifecycleState::Available)],
                effective_at: chrono::Utc::now() - chrono::Duration::days(1),
                expires_at: None,
                active: true,
            },
        )
        .await;
        tx.commit().await.unwrap();
    }
    // Available 批次 + 所有权（owner=企业）——事件日志为空 = 建档态 Created，
    // 直改批次档案状态不足以驱动迁移，补一条 created→…→available 事件
    // 最短路径：created→produced→inspected→available（custody 动作直铺）
    seed_available_batch(&pool, "bt-e2e-rc", "pd-e2e-rc", &enterprise).await;
    let eng = engine(pool.clone());
    let batch = serde_json::json!({"type": "batch", "id": "bt-e2e-rc"});
    for (i, (to, lifecycle)) in [
        ("did:vg:user:rc-cust-a", "produced"),
        ("did:vg:user:rc-cust-b", "inspected"),
        ("did:vg:user:rc-cust-c", "available"),
    ]
    .into_iter()
    .enumerate()
    {
        eng.execute(raw(
            &format!("rc-l{i}"),
            IntentAction::UpdateCustody,
            &enterprise,
            serde_json::json!({
                "subject": batch, "to": to, "reason": "handover", "lifecycle_to": lifecycle
            }),
        ))
        .await
        .unwrap();
    }
    assert_eq!(
        batch_active_state(&pool, "bt-e2e-rc").await,
        (true, "available".into())
    );

    // 签发 FoodSafety VC
    eng.execute(raw(
        "rc-1",
        IntentAction::IssueCredential,
        &regulator,
        serde_json::json!({
            "subject": batch, "holder": enterprise.to_string(),
            "ctype": "food_safety_inspection",
            "claims": {"result": "passed"},
            "credential_id": "vc-e2e-rc-1"
        }),
    ))
    .await
    .unwrap();
    assert_eq!(cred_status(&pool, "vc-e2e-rc-1").await, "valid");

    // 撤销 → 自动召回
    let revoke = eng
        .execute(raw(
            "rc-2",
            IntentAction::RevokeCredential,
            &regulator,
            serde_json::json!({
                "subject": batch, "credential_id": "vc-e2e-rc-1", "reason": "复检不合格"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(revoke.status, IntentStatus::Confirmed);
    assert_eq!(cred_status(&pool, "vc-e2e-rc-1").await, "revoked");
    assert_eq!(
        batch_active_state(&pool, "bt-e2e-rc").await,
        (true, "recalled".into())
    );
    let compliance: (bool,) =
        sqlx::query_as("SELECT compliance_ok FROM batches WHERE id = 'bt-e2e-rc'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!compliance.0, "召回联动 compliance_ok=false");
    let recall_events: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT from_state, to_state, reason FROM lifecycle_events \
         WHERE subject = 'batch:bt-e2e-rc' AND to_state = 'recalled'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(recall_events.len(), 1);
    assert_eq!(recall_events[0].0, "available");
    assert!(
        recall_events[0]
            .2
            .as_deref()
            .is_some_and(|r| r.contains("food_safety_inspection")),
        "reason 列出缺失凭证：{:?}",
        recall_events[0].2
    );
    let mut evs = outbox_types(&pool, "rc-2").await;
    evs.sort();
    assert_eq!(evs, vec!["credential_revoked", "product_recalled"]);

    // 重签发 → policy 恢复边 + 凭证补齐 → 恢复 Available
    let reissue = eng
        .execute(raw(
            "rc-3",
            IntentAction::IssueCredential,
            &regulator,
            serde_json::json!({
                "subject": batch, "holder": enterprise.to_string(),
                "ctype": "food_safety_inspection",
                "claims": {"result": "passed"},
                "credential_id": "vc-e2e-rc-2"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(reissue.status, IntentStatus::Confirmed);
    assert_eq!(
        batch_active_state(&pool, "bt-e2e-rc").await,
        (true, "available".into()),
        "重签发后自动恢复 Available"
    );
    let compliance: (bool,) =
        sqlx::query_as("SELECT compliance_ok FROM batches WHERE id = 'bt-e2e-rc'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(compliance.0, "恢复联动 compliance_ok=true");
    let restore: (String, String, Option<i64>) = sqlx::query_as(
        "SELECT from_state, to_state, policy_version FROM lifecycle_events \
         WHERE subject = 'batch:bt-e2e-rc' AND from_state = 'recalled'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(restore, ("recalled".into(), "available".into(), Some(1)));

    // 账本：credential_status 锚 3 条（issue+revoke+reissue 各一）
    assert_eq!(
        anchor_count(&pool, "credential_status").await,
        3,
        "issue/revoke/reissue 各一"
    );
}

// =====================================================================
// 场景 5：意图幂等（同 id 同 nonce 重放零副作用；同 nonce 异 id 拒绝）
// =====================================================================

#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn idempotent_intent(pool: sqlx::PgPool) {
    use vg_domain::identity::capability::Action as Cap;

    let enterprise = did("did:vg:user:ent-e2e-idem");
    let buyer = did("did:vg:user:buyer-e2e-idem");
    seed_party(
        &pool,
        &enterprise,
        SubjectKind::Enterprise,
        &[Cap::CreateBatch, Cap::TransferOwnership],
    )
    .await;
    seed_product(&pool, "pd-e2e-idem", "food").await;

    let eng = engine(pool.clone());
    let batch = serde_json::json!({"type": "batch", "id": "bt-e2e-idem"});

    // 两个 intent：建档（停 Created）+ 转移
    let create_payload = serde_json::json!({
        "subject": batch, "product_id": "pd-e2e-idem", "quantity": 10, "unit": "kg"
    });
    let transfer_payload = serde_json::json!({
        "subject": batch, "to": buyer.to_string(), "c2c": false
    });
    let ri_create = raw(
        "id-1",
        IntentAction::CreateBatch,
        &enterprise,
        create_payload.clone(),
    );
    let ri_transfer = raw(
        "id-2",
        IntentAction::TransferProduct,
        &enterprise,
        transfer_payload.clone(),
    );
    let nonce_create = ri_create.nonce;
    let r1 = eng.execute(ri_create).await.unwrap();
    assert_eq!(r1.status, IntentStatus::Confirmed);
    let r2 = eng.execute(ri_transfer).await.unwrap();
    assert_eq!(r2.status, IntentStatus::Confirmed);
    assert_eq!(r2.result_ref.as_deref(), Some("tr:id-2"));

    // 基线快照
    let snapshot = table_counts(&pool).await;
    assert_eq!(snapshot.intents, 2);
    assert_eq!(snapshot.audit_events, 2);
    assert_eq!(snapshot.ledger_anchors, 1);

    // 同 RawIntent（同 id 同 nonce）重放 → 同 IntentResult、零副作用
    let replay = eng
        .execute(raw_with_nonce(
            "id-2",
            IntentAction::TransferProduct,
            &enterprise,
            transfer_payload,
            ri_transfer_nonce(&pool, "id-2").await,
        ))
        .await
        .unwrap();
    assert_eq!(replay.status, IntentStatus::Confirmed);
    assert_eq!(replay.result_ref, r2.result_ref, "重放返回同 IntentResult");
    assert!(!replay.awaiting_approval);
    let after = table_counts(&pool).await;
    assert_eq!(after, snapshot, "重放后全表计数零变化");

    // 同 nonce 异 id → ReplayDetected
    let err = eng
        .execute(raw_with_nonce(
            "id-3",
            IntentAction::CreateBatch,
            &enterprise,
            create_payload,
            nonce_create,
        ))
        .await
        .unwrap_err();
    match err {
        AppError::Domain(DomainError::ReplayDetected) => {}
        other => panic!("同 nonce 异 id 应报 ReplayDetected，实际：{other:?}"),
    }
    assert_eq!(
        table_counts(&pool).await,
        snapshot,
        "重放拒绝不得留任何写入"
    );
    assert_eq!(
        ownership_row(&pool, "batch:bt-e2e-idem").await,
        (buyer.to_string(), 1, 0)
    );
}

/// 从库中读回指定 intent 的 nonce（重放必须逐字节同 (id, nonce)）。
async fn ri_transfer_nonce(pool: &sqlx::PgPool, id: &str) -> u64 {
    let (n,): (i64,) = sqlx::query_as("SELECT nonce FROM intents WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
    n as u64
}
