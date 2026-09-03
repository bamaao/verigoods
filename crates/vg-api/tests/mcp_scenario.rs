//! Task 25 MCP 集成测试（feature `mcp-mock-auth` 下编译）。
//!
//! 客户端侧用 rmcp 的 in-process transport（`tokio::io::duplex` +
//! `ServiceExt::serve`），无 HTTP 层——因此鉴权桥走 mock 直通
//! （固定测试 DID），重点验证：工具全集发现、create_batch 走通意图
//! 管道并落库、资源模板/读取、提示词渲染。HTTP 层的鉴权覆盖
//! （无签名 POST /mcp → 401）在无 feature 依赖的 `unsigned_mcp_is_401`
//! 单测中用真 Router + oneshot 验证（该测试不依赖 mock feature，
//! 但同文件编译门控下二者一起跑）。

#![cfg(feature = "mcp-mock-auth")]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use serde_json::{json, Value};
use tower::ServiceExt as _;
use vg_api::mcp::McpServer;
use vg_api::state::{AppState, NonceStore, SharedState};
use vg_application::{AppDeps, HandlerMap, IntentEngine};
use vg_domain::identity::ports::IdentityRepository;
use vg_domain::identity::{Capability, DidDocument, KeyType, SubjectKind, VerificationMethod};
use vg_domain::shared::{Did, Hash32};
use vg_infra_crypto::KeyPair;
use vg_infra_pg::*;
use vg_domain::commodity::ports::CommodityRepository;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientInfo, ContentBlock, GetPromptRequestParams,
    ReadResourceRequestParams,
};
use rmcp::ClientHandler;

// ---------- fixture（与 rest_scenario 同款装配） ----------

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

/// mock-auth 固定测试 DID（与 `mcp::actor_from_context` 的直通值一致）。
fn mock_did() -> Did {
    Did::parse(&format!("did:vg:{}", "22".repeat(32))).unwrap()
}

/// 为 mock DID 落 DID 文档 + 指定能力（授权方 = 主体自身，Phase1 口径）。
async fn seed_mock_identity(pool: &sqlx::PgPool, caps: &[vg_domain::identity::Action]) {
    let did = mock_did();
    // 文档公钥摘要无对应私钥也无妨：MCP in-process 不走 VG-SIG 验签
    let kp = KeyPair::generate();
    let method = VerificationMethod::new("k-0", KeyType::Secp256k1, kp.pubkey_digest(), did.clone());
    let doc = DidDocument {
        did: did.clone(),
        kind: SubjectKind::Enterprise,
        methods: vec![method],
        parent: None,
        jurisdiction: Some("cn".into()),
        created_at: Utc::now(),
    };
    let repo = PgIdentityRepo;
    let mut tx = pool.begin().await.unwrap();
    repo.save_document(&mut tx, &doc).await.unwrap();
    for action in caps {
        let cap = Capability::new(did.clone(), *action, did.clone(), None).unwrap();
        repo.grant_capability(&mut tx, &cap).await.unwrap();
    }
    tx.commit().await.unwrap();
}

/// 建产品档案（create_batch 前置）。
async fn seed_product(pool: &sqlx::PgPool, product_id: &str) {
    let product = vg_domain::commodity::ProductType::new(
        vg_domain::shared::ProductId::new(product_id),
        "food".to_owned(),
        Hash32::from_hex(&format!("0x{}", "ab".repeat(32))).unwrap(),
    )
    .unwrap();
    let repo = PgCommodityRepo;
    let mut tx = pool.begin().await.unwrap();
    repo.save_product(&mut tx, &product).await.unwrap();
    tx.commit().await.unwrap();
}

/// 最小客户端 handler。
#[derive(Debug, Clone, Default)]
struct DummyClientHandler;

impl ClientHandler for DummyClientHandler {
    fn get_info(&self) -> ClientInfo {
        ClientInfo::default()
    }
}

/// 起一对 in-process（server, client）。
async fn in_process(state: SharedState) -> rmcp::service::RunningService<rmcp::RoleClient, DummyClientHandler> {
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server = McpServer::new(state);
    tokio::spawn(async move {
        use rmcp::ServiceExt as _;
        // 保活：必须持有 RunningService 并等待（drop 会关闭 transport）
        let running = server.serve(server_transport).await.expect("server serve");
        let _ = running.waiting().await;
    });
    use rmcp::ServiceExt as _;
    DummyClientHandler.serve(client_transport).await.unwrap()
}

/// 工具结果 → 首个文本 content 解析为 JSON。
fn tool_json(result: &CallToolResult) -> Value {
    let text = result
        .content
        .first()
        .map(|c| match c {
            ContentBlock::Text(t) => t.text.clone(),
            _ => String::new(),
        })
        .unwrap_or_default();
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

fn args(v: Value) -> rmcp::model::JsonObject {
    v.as_object().unwrap().clone()
}

// ---------- 测试 ----------

/// tools/list 含全部 19 个工具名。
#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn tools_list_contains_all(pool: sqlx::PgPool) {
    let client = in_process(test_state(pool)).await;
    let tools = client.list_all_tools().await.unwrap();
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    let expected = [
        // commodity
        "mcp_create_batch", "mcp_split_batch", "mcp_merge_batch", "mcp_create_item", "mcp_get_batch",
        // ownership
        "mcp_get_ownership", "mcp_get_custody",
        // transaction
        "mcp_transfer_product", "mcp_update_custody", "mcp_get_intent", "mcp_approve_intent",
        "mcp_list_transfers",
        // credential
        "mcp_issue_credential", "mcp_revoke_credential", "mcp_list_credentials",
        // compliance
        "mcp_check_compliance", "mcp_get_required_credentials",
        // zk
        "mcp_scan_shielded_notes", "mcp_get_proof",
    ];
    for want in expected {
        assert!(names.contains(&want.to_string()), "缺少工具 {want}，实际：{names:?}");
    }
    assert_eq!(names.len(), expected.len(), "工具数应恰为 19：{names:?}");
}

/// create_batch 工具走通意图管道：Confirmed + 批次落库。
#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn create_batch_tool_walks_pipeline(pool: sqlx::PgPool) {
    use vg_domain::identity::Action;
    seed_mock_identity(&pool, &[Action::CreateBatch]).await;
    seed_product(&pool, "pd-pork").await;
    let state = test_state(pool.clone());
    let client = in_process(state.clone()).await;

    let result = client
        .call_tool(
            CallToolRequestParams::new("mcp_create_batch").with_arguments(args(json!({
                "batch_id": "bt-mcp-1",
                "product_id": "pd-pork",
                "quantity": 100,
                "unit": "kg",
            }))),
        )
        .await
        .unwrap();
    assert_ne!(result.is_error, Some(true), "create_batch 不应失败");
    let v = tool_json(&result);
    assert_eq!(v["status"], "confirmed", "意图应直达 Confirmed：{v}");
    assert_eq!(v["result_ref"], "bt-mcp-1");

    // 落库断言：聚合视图（工具）与所有权档案
    let view = client
        .call_tool(
            CallToolRequestParams::new("mcp_get_batch").with_arguments(args(json!({
                "id": "bt-mcp-1",
            }))),
        )
        .await
        .unwrap();
    let view = tool_json(&view);
    assert_eq!(view["batch"]["id"], "bt-mcp-1", "{view}");
    assert_eq!(view["state"], "created");
    assert_eq!(view["transfer_count"], 0);
}

/// 资源：模板存在 + 读取一个 batch 返回聚合 JSON。
#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn resources_templates_and_read(pool: sqlx::PgPool) {
    use vg_domain::identity::Action;
    seed_mock_identity(&pool, &[Action::CreateBatch]).await;
    seed_product(&pool, "pd-pork").await;
    let client = in_process(test_state(pool.clone())).await;

    // 模板存在
    let templates = client.list_all_resource_templates().await.unwrap();
    let uris: Vec<String> = templates.iter().map(|t| t.uri_template.to_string()).collect();
    for want in [
        "commodity://batch/{id}",
        "commodity://asset/{id}",
        "commodity://product/{id}",
    ] {
        assert!(uris.contains(&want.to_string()), "缺少模板 {want}：{uris:?}");
    }

    // 先经工具建批，再读资源
    client
        .call_tool(
            CallToolRequestParams::new("mcp_create_batch").with_arguments(args(json!({
                "batch_id": "bt-res-1",
                "product_id": "pd-pork",
                "quantity": 10,
                "unit": "kg",
            }))),
        )
        .await
        .unwrap();
    let read = client
        .read_resource(ReadResourceRequestParams::new("commodity://batch/bt-res-1"))
        .await
        .unwrap();
    let text = match read.contents.first().unwrap() {
        rmcp::model::ResourceContents::TextResourceContents { text, .. } => text.clone(),
        _ => panic!("资源内容应为文本"),
    };
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["batch"]["id"], "bt-res-1");
    assert!(v["lineage"].is_array());
}

/// 提示词：8 条 + get 一个渲染（参数占位替换）。
#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn prompts_list_and_render(pool: sqlx::PgPool) {
    let client = in_process(test_state(pool)).await;
    let prompts = client.list_all_prompts().await.unwrap();
    let names: Vec<String> = prompts.iter().map(|p| p.name.to_string()).collect();
    let expected = [
        "batch_trace_report",
        "recall_investigation",
        "compliance_checklist",
        "transfer_guide",
        "consumer_verify",
        "regulatory_disclosure",
        "custody_handover",
        "lineage_dispute",
    ];
    assert_eq!(names.len(), 8, "提示词应恰为 8 条：{names:?}");
    for want in expected {
        assert!(names.contains(&want.to_string()), "缺少提示词 {want}");
    }

    let got = client
        .get_prompt(
            GetPromptRequestParams::new("recall_investigation").with_arguments(args(json!({
                "subject": "batch:bt-1",
                "reason": "检出致病菌",
            }))),
        )
        .await
        .unwrap();
    assert_eq!(got.messages.len(), 1);
    let text = match &got.messages[0].content {
        ContentBlock::Text(t) => t.text.clone(),
        _ => panic!("提示词消息应为文本"),
    };
    assert!(text.contains("batch:bt-1"), "应渲染 subject 占位：{text}");
    assert!(text.contains("检出致病菌"), "应渲染 reason 占位：{text}");
}

/// 鉴权桥（HTTP 层）：无签名 POST /mcp → 401（VG-SIG 中间件覆盖）。
#[sqlx::test(migrations = "../vg-infra-pg/migrations")]
async fn unsigned_mcp_post_is_401(pool: sqlx::PgPool) {
    let router = vg_api::build_router(test_state(pool));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
        ))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "无签名 /mcp 应 401");
}
