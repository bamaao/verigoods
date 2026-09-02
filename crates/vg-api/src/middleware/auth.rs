//! VG-SIG 请求签名鉴权中间件。
//!
//! ## 消息格式（写死契约）
//!
//! ```text
//! vg:sig:v1\n{METHOD}\n{path}\n{ts}\n{nonce}
//! ```
//!
//! - `vg:sig:v1` 为域分隔标签（vg-infra-crypto keypair 的域分隔契约
//!   要求调用方自行包含，防止跨协议签名重放）；
//! - `METHOD` 大写 HTTP 方法，`path` 为不含 query 的路径；
//! - 签名口径：`ecdsa_recoverable(keccak256(msg))`，
//!   **编码为 65 字节 `r||s||v` hex（`0x` 前缀，130 个 hex 字符）**，
//!   `v` 携带 RecoveryId（27/28 或 0/1 均接受，解析时归一化）。
//!
//! ## 验证流程
//!
//! 1. 白名单直通：`/health`，或 `GET /api/v1/consumer`、
//!    `GET /api/v1/consumer/*`（精确段匹配，排除前缀碰撞路径；只读免签，
//!    不注入 `AuthedDid`）；
//! 2. 解析 `VG-SIG` 头：`did="...", sig="0x...", ts=..., nonce="..."`，
//!    各字段严格格式校验（防注入）：did=`did:vg:`+64hex、sig=0x+130hex、
//!    ts=纯数字、nonce=`[A-Za-z0-9-_]{1,64}`；畸形一律 401；
//! 3. ts 漂移：`|now - ts| > 300` → 401；
//! 4. 短事务 `find_document`（begin + find + commit；仓储 Context 绑定
//!    事务，开销可接受）→ 无文档或无活跃公钥（全撤销）→ 401；
//! 5. 恢复公钥：比对 `keccak256(压缩 sec1 33B)` 与活跃方法
//!    `public_key` 字段（字段存的就是摘要，无需再哈希以外处理）；
//!    不符 → 401；
//! 6. **签名验证通过后**才 `check_and_record` nonce（定案取舍：同 nonce
//!    的假签名请求不烧毁真签名的可用性；代价是失败签名请求不占
//!    nonce 预算，可接受）；
//! 7. 注入 [`AuthedDid`] extension 放行。
//!
//! 401 响应体走 [`ApiError`] 统一 JSON。

use axum::extract::State;
use axum::http::{Method, Request, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use k256::ecdsa::{RecoveryId, Signature};
use std::sync::Arc;
use vg_domain::identity::ports::IdentityRepository;
use vg_domain::shared::Did;
use vg_infra_crypto::keccak256;

use crate::error::ApiError;
use crate::state::{AppState, SharedState};

/// ts 允许的时钟漂移上限（秒）。
const MAX_CLOCK_DRIFT_SECS: i64 = 300;

/// 鉴权通过后注入的请求扩展：签名者 DID。
#[derive(Debug, Clone)]
pub struct AuthedDid(pub Did);

/// VG-SIG 头解析产物。
#[derive(Debug, Clone, PartialEq, Eq)]
struct SigHeader {
    did: String,
    /// 65 字节 `r||s||v`（v 已归一化为原始 RecoveryId 数值 0/1）。
    sig65: [u8; 65],
    ts: i64,
    nonce: String,
}

/// 构造待签名消息（pub 化供客户端 SDK / 测试复用同一口径）。
pub fn sign_message(method: &Method, path: &str, ts: i64, nonce: &str) -> String {
    format!(
        "vg:sig:v1\n{}\n{}\n{}\n{}",
        method.as_str().to_ascii_uppercase(),
        path,
        ts,
        nonce
    )
}

/// 鉴权中间件（`middleware::from_fn_with_state` 装载）。
pub async fn vg_sig_auth(
    State(state): State<SharedState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let uri: Uri = req.uri().clone();
    let path = uri.path().to_owned();

    // 白名单：/health 与 consumer 只读（精确段匹配：段本身或段内子路径，
    // 排除 /api/v1/consumer-admin、/api/v1/consumerfoo 等前缀碰撞）
    if path == "/health"
        || (method == Method::GET
            && (path == "/api/v1/consumer" || path.starts_with("/api/v1/consumer/")))
    {
        return next.run(req).await;
    }

    // 解析 + 校验头（VG-SIG 头必须恰好出现一次；重复出现视为注入尝试 → 401）
    let mut sig_values = req.headers().get_all("VG-SIG").iter();
    let raw = match (sig_values.next(), sig_values.next()) {
        (Some(v), None) => v.to_str(),
        _ => {
            tracing::warn!(%path, reason = "header_missing_or_duplicated", "鉴权拒绝：VG-SIG 头缺失或重复出现");
            return ApiError::unauthorized("VG-SIG 头缺失或格式非法").into_response();
        }
    };
    let header = match raw.ok().and_then(parse_sig_header) {
        Some(h) => h,
        None => {
            tracing::warn!(%path, reason = "header_malformed", "鉴权拒绝：VG-SIG 头格式非法");
            return ApiError::unauthorized("VG-SIG 头缺失或格式非法").into_response();
        }
    };

    // ts 漂移检查
    let now = chrono::Utc::now().timestamp();
    if (now - header.ts).abs() > MAX_CLOCK_DRIFT_SECS {
        tracing::warn!(did = %header.did, %path, reason = "timestamp_drift", ts = header.ts, "鉴权拒绝：时间戳漂移超限");
        return ApiError::unauthorized("VG-SIG 时间戳漂移超限（±300s）").into_response();
    }

    // DID 解析 → 文档查询（短事务：begin + find + commit）
    let did = match Did::parse(&header.did) {
        Ok(d) => d,
        Err(_) => {
            tracing::warn!(did = %header.did, %path, reason = "did_invalid", "鉴权拒绝：DID 语法非法");
            return ApiError::unauthorized("VG-SIG DID 非法").into_response();
        }
    };
    let doc = match find_document(&state, &did).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            tracing::warn!(did = did.as_str(), %path, reason = "did_not_found", "鉴权拒绝：签名者 DID 文档不存在");
            return ApiError::unauthorized("VG-SIG 签名者 DID 文档不存在").into_response();
        }
        Err(e) => {
            tracing::warn!(did = did.as_str(), %path, reason = "storage_error", error = %e, "鉴权拒绝：DID 文档查询存储错误");
            return ApiError::from(e).into_response();
        }
    };
    let Some(active) = doc.active_pubkey() else {
        tracing::warn!(did = did.as_str(), %path, reason = "all_keys_revoked", "鉴权拒绝：签名者无活跃公钥");
        return ApiError::unauthorized("VG-SIG 签名者无活跃公钥（全部已撤销）").into_response();
    };

    // 恢复公钥并比对摘要（字段存的就是 keccak(33B 压缩) 摘要）
    let msg = sign_message(&method, &path, header.ts, &header.nonce);
    let recovered_digest = match recover_digest(&header.sig65, msg.as_bytes()) {
        Ok(d) => d,
        Err(_) => {
            tracing::warn!(did = did.as_str(), %path, reason = "signature_recover_failed", "鉴权拒绝：签名恢复失败");
            return ApiError::unauthorized("VG-SIG 签名恢复失败").into_response();
        }
    };
    if recovered_digest != *active.public_key.as_bytes() {
        tracing::warn!(did = did.as_str(), %path, reason = "signature_mismatch", "鉴权拒绝：签名与活跃公钥不匹配");
        return ApiError::unauthorized("VG-SIG 签名与活跃公钥不匹配").into_response();
    }

    // 签名已验证通过：记录 nonce（重放即 401）
    if !state.nonce_store.check_and_record(&header.nonce, header.ts) {
        tracing::warn!(did = did.as_str(), %path, reason = "nonce_replay", nonce = %header.nonce, "鉴权拒绝：nonce 已使用（重放）");
        return ApiError::unauthorized("VG-SIG nonce 已使用（重放）").into_response();
    }

    let mut req = req;
    req.extensions_mut().insert(AuthedDid(did));
    next.run(req).await
}

/// 解析 `VG-SIG: did="...", sig="0x...", ts=..., nonce="..."`。
///
/// 各字段严格格式校验（防注入契约）：
/// - did：`did:vg:` + 64 个小写 hex；
/// - sig：`0x` + 130 个 hex（65 字节 r||s||v）；
/// - ts：纯数字（i64 秒）；
/// - nonce：`[A-Za-z0-9-_]{1,64}`。
fn parse_sig_header(raw: &str) -> Option<SigHeader> {
    // 重复键拒绝：同一键出现两次视为注入尝试（值字符集均不含 '='/'"'，
    // 键模式不会在合法值内误命中）
    if raw.matches("did=\"").count() != 1
        || raw.matches("sig=\"").count() != 1
        || raw.matches("ts=").count() != 1
        || raw.matches("nonce=\"").count() != 1
    {
        return None;
    }
    let did = extract_quoted(raw, "did")?;
    let sig = extract_quoted(raw, "sig")?;
    let ts = extract_bare(raw, "ts")?;
    let nonce = extract_quoted(raw, "nonce")?;

    // did 严格格式
    let did_suffix = did.strip_prefix("did:vg:")?;
    if did_suffix.len() != 64 || !did_suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // sig 严格格式：0x + 130 hex → 65 字节，v 归一化
    let sig_hex = sig.strip_prefix("0x")?;
    if sig_hex.len() != 130 || !sig_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(sig_hex).ok()?;
    let mut sig65: [u8; 65] = bytes.try_into().ok()?;
    let v = match sig65[64] {
        27 | 28 => sig65[64] - 27,
        0 | 1 => sig65[64],
        _ => return None,
    };
    sig65[64] = v;
    // ts 纯数字
    if ts.is_empty() || !ts.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ts: i64 = ts.parse().ok()?;
    // nonce 安全字符集
    if nonce.is_empty()
        || nonce.len() > 64
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }

    Some(SigHeader {
        did,
        sig65,
        ts,
        nonce,
    })
}

/// 提取 `key="value"` 形式的带引号字段（值内禁止引号，防转义注入）。
fn extract_quoted(raw: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=\"");
    let start = raw.find(&pat)? + pat.len();
    let rest = &raw[start..];
    let end = rest.find('"')?;
    // 值内出现引号说明结构异常（find 已保证首个引号截断，剩余校验交由上层格式检查）
    Some(rest[..end].to_owned())
}

/// 提取 `key=value` 形式的裸字段（到下一个逗号或串尾）。
fn extract_bare(raw: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=");
    let start = raw.find(&pat)? + pat.len();
    let rest = &raw[start..];
    let end = rest.find(',').unwrap_or(rest.len());
    Some(rest[..end].trim().to_owned())
}

/// 短事务查询 DID 文档（begin + find + commit）。
async fn find_document(
    state: &Arc<AppState>,
    did: &Did,
) -> Result<Option<vg_domain::identity::DidDocument>, vg_domain::shared::DomainError> {
    let repo = vg_infra_pg::PgIdentityRepo;
    let mut tx = state.pool.begin().await.map_err(|e| {
        vg_domain::shared::DomainError::Storage(format!("鉴权事务开启失败：{e}"))
    })?;
    let doc = repo.find_document(&mut tx, did).await?;
    tx.commit().await.map_err(|e| {
        vg_domain::shared::DomainError::Storage(format!("鉴权事务提交失败：{e}"))
    })?;
    Ok(doc)
}

/// 由 65 字节签名恢复公钥摘要：`keccak256(recovered 压缩 sec1 33B)`。
///
/// 任何密码学失败（签名非法 / 恢复失败 / rid 越界）统一折叠为 `Err(())`，
/// 由调用方以 401 拒绝——不向客户端泄露具体失败原因。
fn recover_digest(sig65: &[u8; 65], msg: &[u8]) -> Result<[u8; 32], ()> {
    let sig = Signature::from_slice(&sig65[..64]).map_err(|_| ())?;
    // 上游已把 v 归一化为 0/1（is_y_odd），无 x 归约标志
    let rid = RecoveryId::new(sig65[64] == 1, false);
    let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(&keccak256(msg), &sig, rid)
        .map_err(|_| ())?;
    // 直接压缩编码（33B sec1），不做 65B 解压往返
    let compressed = vk.to_encoded_point(true);
    Ok(keccak256(compressed.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use chrono::Utc;
    use tower::ServiceExt;
    use vg_domain::identity::{DidDocument, KeyType, SubjectKind, VerificationMethod};
    use vg_infra_crypto::KeyPair;

    use crate::state::{NonceStore, NONCE_CAPACITY};

    // ---------- 纯逻辑单测（无 DB） ----------

    #[test]
    fn sign_message_format_is_locked() {
        let m = sign_message(&Method::GET, "/api/v1/x", 1000, "n-1");
        assert_eq!(m, "vg:sig:v1\nGET\n/api/v1/x\n1000\nn-1");
    }

    #[test]
    fn parse_header_accepts_valid_and_normalizes_v() {
        let mut sig = [0u8; 65];
        sig[..64].copy_from_slice(&[0x11u8; 64]);
        sig[64] = 28;
        let raw = format!(
            "did=\"did:vg:{}\", sig=\"0x{}\", ts=42, nonce=\"abc-DEF_01\"",
            "a".repeat(64),
            hex::encode(sig)
        );
        let h = parse_sig_header(&raw).expect("合法头应解析成功");
        assert_eq!(h.sig65[64], 1, "v=28 应归一化为 RecoveryId 1");
        assert_eq!(h.ts, 42);
        assert_eq!(h.nonce, "abc-DEF_01");
    }

    #[test]
    fn parse_header_rejects_malformed_fields() {
        let mk = |did: &str, sig: &str, ts: &str, nonce: &str| {
            format!("did=\"{did}\", sig=\"{sig}\", ts={ts}, nonce=\"{nonce}\"")
        };
        let valid_sig = {
            let mut s = [0u8; 65];
            s[..64].copy_from_slice(&[0x22u8; 64]);
            s[64] = 27;
            format!("0x{}", hex::encode(s))
        };
        let good_did = format!("did:vg:{}", "b".repeat(64));
        // 基线合法
        assert!(parse_sig_header(&mk(&good_did, &valid_sig, "1", "n")).is_some());
        // 各字段畸形一轮
        assert!(parse_sig_header(&mk("did:vg:short", &valid_sig, "1", "n")).is_none());
        assert!(parse_sig_header(&mk("did:vg:zz<<>", &valid_sig, "1", "n")).is_none());
        assert!(parse_sig_header(&mk(&good_did, "0x1234", "1", "n")).is_none());
        assert!(parse_sig_header(&mk(&good_did, &valid_sig[..131], "1", "n")).is_none());
        assert!(parse_sig_header(&mk(&good_did, &valid_sig, "12x", "n")).is_none());
        assert!(parse_sig_header(&mk(&good_did, &valid_sig, "-5", "n")).is_none());
        assert!(parse_sig_header(&mk(&good_did, &valid_sig, "1", "带空格 n")).is_none());
        assert!(parse_sig_header(&mk(&good_did, &valid_sig, "1", &"x".repeat(65))).is_none());
    }

    #[test]
    fn parse_header_rejects_duplicate_keys() {
        let mk = |extra: &str| {
            format!(
                "did=\"did:vg:{}\", {extra}, sig=\"0x{}\", ts=1, nonce=\"n\"",
                "c".repeat(64),
                {
                    let mut s = [0u8; 65];
                    s[..64].copy_from_slice(&[0x33u8; 64]);
                    s[64] = 27;
                    hex::encode(s)
                }
            )
        };
        assert!(parse_sig_header(&mk("k=\"无关\"")).is_some(), "基线应合法");
        // 同键出现两次 → 拒绝
        assert!(parse_sig_header(&mk(&format!("did=\"did:vg:{}\"", "d".repeat(64)))).is_none());
        assert!(parse_sig_header(&mk("nonce=\"m\"")).is_none());
        assert!(parse_sig_header(&mk("ts=2")).is_none());
        // sig 重复需要键模式出现两次：第二份完整 sig 字段
        let dup_sig = {
            let mut s = [0u8; 65];
            s[..64].copy_from_slice(&[0x44u8; 64]);
            s[64] = 27;
            format!("sig=\"0x{}\"", hex::encode(s))
        };
        assert!(parse_sig_header(&mk(&dup_sig)).is_none());
    }

    #[test]
    fn nonce_store_dedup_and_capacity_eviction() {
        let s = NonceStore::new();
        assert!(s.check_and_record("a", 1));
        assert!(!s.check_and_record("a", 1), "重复 nonce 应拒绝");
        assert!(s.check_and_record("b", 0));
        // 容量超限淘汰最旧 ts（b=0）
        for i in 0..NONCE_CAPACITY {
            assert!(s.check_and_record(&format!("n{i}"), 10 + i as i64));
        }
        let seen = s.seen.lock().unwrap();
        assert!(seen.len() <= NONCE_CAPACITY);
        assert!(!seen.contains_key("b"), "最旧条目应被淘汰");
        drop(seen);
        // 被淘汰的 b 可再次记录（内存级防重放的既定取舍）
        assert!(s.check_and_record("b", 99));
    }

    // ---------- 集成测试（真库） ----------

    /// fixture：密钥对 + 对应 DID 文档落库（返回 KeyPair）。
    async fn seed_identity(pool: &sqlx::PgPool, revoked_only: bool) -> KeyPair {
        let kp = KeyPair::generate();
        let did = Did::parse(&vg_infra_crypto::pubkey_to_did(kp.public())).unwrap();
        let mut method = VerificationMethod::new(
            "k-0",
            KeyType::Secp256k1,
            kp.pubkey_digest(),
            did.clone(),
        );
        method.revoked = revoked_only;
        let doc = DidDocument {
            did,
            kind: SubjectKind::Enterprise,
            methods: vec![method],
            parent: None,
            jurisdiction: None,
            created_at: Utc::now(),
        };
        let repo = vg_infra_pg::PgIdentityRepo;
        let mut tx = pool.begin().await.unwrap();
        repo.save_document(&mut tx, &doc).await.unwrap();
        tx.commit().await.unwrap();
        kp
    }

    /// 测试 router：直接复用生产 [`crate::build_router`]（内含
    /// `#[cfg(test)]` 测试保护路由 `__test_protected` 与 consumer 测试路由）。
    fn test_router(state: SharedState) -> Router {
        crate::build_router(state)
    }

    fn state(pool: sqlx::PgPool) -> SharedState {
        Arc::new(AppState {
            engine: test_engine(pool.clone()),
            pool,
            nonce_store: NonceStore::new(),
        })
    }

    /// 最小 IntentEngine（中间件测试不触达，仅装配非空）。
    fn test_engine(pool: sqlx::PgPool) -> vg_application::IntentEngine {
        use std::sync::Arc;
        use vg_application::{HandlerMap, IntentEngine};
        use vg_infra_pg::*;
        let deps = vg_application::AppDeps {
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
            prover: Arc::new(vg_infra_zk::dispatcher::ProverDispatcher),
            hasher: Arc::new(vg_infra_crypto::PoseidonNoteHasher),
        };
        let mut map = HandlerMap::new();
        vg_application::register_default(&mut map);
        IntentEngine::new(deps, map)
    }

    /// 构造带 VG-SIG 头的请求。
    fn signed_req(
        kp: &KeyPair,
        method: &Method,
        path: &str,
        ts: i64,
        nonce: &str,
    ) -> Request<Body> {
        let msg = sign_message(method, path, ts, nonce);
        let (sig, rid) = kp.sign_recoverable(msg.as_bytes()).unwrap();
        let mut s65 = [0u8; 65];
        s65[..64].copy_from_slice(&sig.to_bytes());
        s65[64] = 27 + u8::from(rid.is_y_odd());
        let did = vg_infra_crypto::pubkey_to_did(kp.public());
        Request::builder()
            .method(method.clone())
            .uri(path)
            .header(
                "VG-SIG",
                format!("did=\"{did}\", sig=\"0x{}\", ts={ts}, nonce=\"{nonce}\"", hex::encode(s65)),
            )
            .body(Body::empty())
            .unwrap()
    }

    async fn send(router: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null)
        };
        (status, v)
    }

    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn good_signature_passes(pool: sqlx::PgPool) {
        let kp = seed_identity(&pool, false).await;
        let router = test_router(state(pool));
        let ts = Utc::now().timestamp();
        let (status, body) = send(
            &router,
            signed_req(&kp, &Method::GET, "/api/v1/__test_protected", ts, "n1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "好签名应放行：{body}");
        assert_eq!(
            body["did"],
            vg_infra_crypto::pubkey_to_did(kp.public()),
            "AuthedDid 应为签名者 DID"
        );
    }

    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn tampered_signature_is_401(pool: sqlx::PgPool) {
        let kp = seed_identity(&pool, false).await;
        let router = test_router(state(pool));
        let ts = Utc::now().timestamp();
        let mut req = signed_req(&kp, &Method::GET, "/api/v1/__test_protected", ts, "n1");
        // 篡改 sig 一个字节
        let hv = req.headers_mut().get_mut("VG-SIG").unwrap();
        let mut s = hv.to_str().unwrap().to_owned();
        let idx = s.find("0x").unwrap() + 4;
        let ch = s.as_bytes()[idx];
        s.replace_range(idx..idx + 1, if ch == b'0' { "1" } else { "0" });
        *hv = s.parse().unwrap();
        let (status, body) = send(&router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "坏签应 401：{body}");
    }

    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn replayed_nonce_is_401(pool: sqlx::PgPool) {
        let kp = seed_identity(&pool, false).await;
        let router = test_router(state(pool));
        let ts = Utc::now().timestamp();
        let first = signed_req(&kp, &Method::GET, "/api/v1/__test_protected", ts, "same");
        let (s1, _) = send(&router, first).await;
        assert_eq!(s1, StatusCode::OK);
        let second = signed_req(&kp, &Method::GET, "/api/v1/__test_protected", ts, "same");
        let (s2, body) = send(&router, second).await;
        assert_eq!(s2, StatusCode::UNAUTHORIZED, "同 nonce 重放应 401：{body}");
    }

    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn stale_timestamp_is_401(pool: sqlx::PgPool) {
        let kp = seed_identity(&pool, false).await;
        let router = test_router(state(pool));
        let ts = Utc::now().timestamp() - 400;
        let (status, _) = send(
            &router,
            signed_req(&kp, &Method::GET, "/api/v1/__test_protected", ts, "n1"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "过期 ts 应 401");
    }

    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn malformed_headers_are_401(pool: sqlx::PgPool) {
        seed_identity(&pool, false).await;
        let router = test_router(state(pool));
        let ts = Utc::now().timestamp();
        let bad_headers = [
            // 缺头
            None,
            // did 畸形
            Some(format!(
                "did=\"did:vg:zz\", sig=\"0x{}\", ts={ts}, nonce=\"n\"",
                hex::encode([1u8; 65])
            )),
            // sig 畸形
            Some(format!(
                "did=\"did:vg:{}\", sig=\"0x00\", ts={ts}, nonce=\"n\"",
                "a".repeat(64)
            )),
            // ts 非数字
            Some(format!(
                "did=\"did:vg:{}\", sig=\"0x{}\", ts=abc, nonce=\"n\"",
                "a".repeat(64),
                hex::encode([1u8; 65])
            )),
            // nonce 非法字符
            Some(format!(
                "did=\"did:vg:{}\", sig=\"0x{}\", ts={ts}, nonce=\"n n\"",
                "a".repeat(64),
                hex::encode([1u8; 65])
            )),
        ];
        for h in bad_headers {
            let mut b = Request::builder()
                .method(Method::GET)
                .uri("/api/v1/__test_protected");
            if let Some(v) = h {
                b = b.header("VG-SIG", v);
            }
            let req = b.body(Body::empty()).unwrap();
            let (status, body) = send(&router, req).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "畸形头应 401：{body}");
        }
    }

    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn whitelist_paths_bypass_signature(pool: sqlx::PgPool) {
        let router = test_router(state(pool));
        // /health 免签
        let (s1, _) = send(
            &router,
            Request::builder().uri("/health").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(s1, StatusCode::OK, "/health 应免签");
        // GET consumer 只读免签
        let (s2, _) = send(
            &router,
            Request::builder()
                .uri("/api/v1/consumer/x")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(s2, StatusCode::OK, "GET consumer 应免签");
        // POST consumer 需签名：无头 401
        let (s3, _) = send(
            &router,
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/consumer/x")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(s3, StatusCode::UNAUTHORIZED, "POST consumer 无签应 401");
    }

    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn whitelist_prefix_collision_paths_require_signature(pool: sqlx::PgPool) {
        let router = test_router(state(pool));
        // /api/v1/consumer-admin、/api/v1/consumerfoo 是独立段，不在白名单内：
        // 无签 GET 一律 401（而非被 starts_with 误放行后的 404）
        for path in ["/api/v1/consumer-admin", "/api/v1/consumerfoo"] {
            let (status, _) = send(
                &router,
                Request::builder().uri(path).body(Body::empty()).unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} 无签应 401");
        }
    }

    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn duplicated_vg_sig_header_line_is_401(pool: sqlx::PgPool) {
        seed_identity(&pool, false).await;
        let router = test_router(state(pool));
        let ts = Utc::now().timestamp();
        let kp = vg_infra_crypto::KeyPair::generate();
        let mut req = signed_req(&kp, &Method::GET, "/api/v1/__test_protected", ts, "n1");
        // 追加第二行同值 VG-SIG 头（HTTP 允许重复头）
        let v = req.headers().get("VG-SIG").unwrap().clone();
        req.headers_mut().append("VG-SIG", v);
        let (status, body) = send(&router, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "重复 VG-SIG 头应 401：{body}");
    }

    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn fully_revoked_keys_are_401(pool: sqlx::PgPool) {
        let kp = seed_identity(&pool, true).await;
        let router = test_router(state(pool));
        let ts = Utc::now().timestamp();
        let (status, _) = send(
            &router,
            signed_req(&kp, &Method::GET, "/api/v1/__test_protected", ts, "n1"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "全撤销公钥应 401");
    }

    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn unknown_did_is_401(pool: sqlx::PgPool) {
        let kp = KeyPair::generate(); // 未落库
        let router = test_router(state(pool));
        let ts = Utc::now().timestamp();
        let (status, _) = send(
            &router,
            signed_req(&kp, &Method::GET, "/api/v1/__test_protected", ts, "n1"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "未知 DID 应 401");
    }
}
