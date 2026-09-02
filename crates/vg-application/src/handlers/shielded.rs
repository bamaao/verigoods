//! ShieldedTransfer 处理器（L3 审批门 + 双隐私模式之 Shielded Transactions）。
//!
//! 流程（顺序严格，doc 锁定）：
//! 1. 构造被花费旧 Note → `nullifier("vg:shield:v1")`；
//! 2. **双花检查**：`ledger.is_nullifier_spent` 在锚定前查（并发双花窗口
//!    由 nullifiers 表 PK + ledger 幂等锚定兜底——后到者插入即冲突回滚）；
//! 3. L3 审批门：approvals 未决 → [`HandlerOutcome::AwaitingApproval`]
//!    （engine 落未决行；**门内不产生任何业务写入**——engine 对
//!    AwaitingApproval 路径直接 commit，若门后有写入会被提前固化）；
//! 4. crypto：接收方 meta-address 实点化 → `derive_one_time`（随机 r）；
//! 5. 新 Note（发送方生成 secret/salt，接收方经扫描 + 私库获取）→
//!    Poseidon2 承诺；
//! 6. ECIES ExtraData（监管 ViewKey 加密 {from,to,asset,ts}，from/to 仅
//!    进密文，明文表/锚定载荷均无交易对手信息）；
//! 7. note_opening 真实 ZK 证明 + verify + proofs 落档
//!    （proof_id = `pf:<intent_id>`）；
//! 8. 三表同事务写入（notes / nullifiers / shielded_txs）；
//! 9. **不发领域事件**：outbox 事件含 subject 明文会泄漏隐私语义，
//!    Phase2 若需要再加脱敏变体（doc 注明取舍）；
//! 10. **悬挂锚契约**：最后依次锚定 Nullifier / Commitment / EncryptedExtra。
//!
//! Phase1 口径：`amount` 必须等于 `old_note.amount`（全额转移、无找零）。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::Deserialize;
use vg_domain::intent::{Intent, IntentAction, IntentStatus};
use vg_domain::ports::{CircuitSpec, FieldElement, LedgerItem};
use vg_domain::privacy::{CompressedPoint, Note, StealthMetaAddress};
use vg_domain::shared::{Did, DomainError, Hash32, ProofId, SubjectRef};
use vg_infra_crypto as crypto;
use vg_infra_pg::ProofRecord;

use crate::deps::{AppDeps, PgTx};
use crate::handlers::{parse_payload, subject_label};
use crate::intent_engine::{HandlerOutcome, IntentHandler};

/// nullifier 域分隔（与 vg-domain Note 契约定案一致，写死）。
const NULLIFIER_CTX: &str = "vg:shield:v1";

/// ShieldedTransfer 载荷。
///
/// JSON Schema（`deny_unknown_fields`，subject 必填为审计兜底）：
///
/// ```json
/// {
///   "subject":      {"type": "batch", "id": "bt-001"},
///   "old_note":     {"secret": "<64hex>", "salt": "<32hex>",
///                    "owner_ot_addr": "<64hex>", "amount": 10},
///   "recipient_meta": {"view_pub": "<66hex>", "spend_pub": "<66hex>"},
///   "amount":       10,
///   "from_did":     "did:vg:user:producer",
///   "to_did":       "did:vg:user:retailer",
///   "regulator_view_pub": "<66hex>"
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShieldedPayload {
    /// 转移客体（批次或单品，审计兜底；承诺编码内的 asset 词亦用它）。
    subject: SubjectRef,
    /// 被花费旧 Note（发送方自持有，明文仅入私有 PG 的 intents 载荷）。
    old_note: OldNoteSpec,
    /// 接收方 meta-address（view/spend 公钥压缩点 hex）。
    recipient_meta: MetaSpec,
    /// 转移金额（Phase1 必须等于 old_note.amount，全额转移无找零）。
    amount: u64,
    /// 监管披露用转出方 DID（仅进 ECIES 密文）。
    from_did: Did,
    /// 监管披露用转入方 DID（仅进 ECIES 密文）。
    to_did: Did,
    /// 监管 ViewKey 公钥（压缩点 hex，ExtraData 加密目标）。
    regulator_view_pub: CompressedPoint,
}

/// 旧 Note 规格（hex 字段手工解码，给出带字段名的错误）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OldNoteSpec {
    /// 旧 Note secret（64 hex = 32 字节）。
    secret: String,
    /// 旧 Note salt（32 hex = 16 字节）。
    salt: String,
    /// 旧 Note 收款方一次性地址摘要（64 hex）。
    owner_ot_addr: Hash32,
    /// 旧 Note 金额。
    amount: u64,
}

/// 接收方 meta-address。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetaSpec {
    /// view 公钥（66 hex 压缩点）。
    view_pub: CompressedPoint,
    /// spend 公钥（66 hex 压缩点）。
    spend_pub: CompressedPoint,
}

impl MetaSpec {
    /// 转领域元地址。
    fn into_meta(self) -> StealthMetaAddress {
        StealthMetaAddress {
            view_pub: self.view_pub,
            spend_pub: self.spend_pub,
        }
    }
}

/// hex 字符串 → 定长字节（错误携带字段名）。
fn decode_fixed<const N: usize>(hex_str: &str, what: &str) -> Result<[u8; N], DomainError> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        DomainError::InvalidInput(format!("{what} 非法 hex：{e}"))
    })?;
    bytes.try_into().map_err(|_| {
        DomainError::InvalidInput(format!("{what} 必须为 {N} 字节 hex"))
    })
}

/// ShieldedTransfer 处理器（L3：监管副签审批门）。
pub struct ShieldedTransferHandler;

#[async_trait]
impl IntentHandler for ShieldedTransferHandler {
    fn action(&self) -> IntentAction {
        IntentAction::ShieldedTransfer
    }

    async fn handle(
        &self,
        deps: &AppDeps,
        tx: &mut PgTx,
        intent: &mut Intent,
        now: DateTime<Utc>,
    ) -> Result<HandlerOutcome, DomainError> {
        let payload: ShieldedPayload = parse_payload(intent)?;

        // Phase1：全额转移（无找零）——金额必须与旧 Note 一致。
        if payload.amount != payload.old_note.amount {
            return Err(DomainError::InvalidInput(format!(
                "转移金额 {} 必须等于旧 Note 金额 {}（Phase1 全额转移，无找零）",
                payload.amount, payload.old_note.amount
            )));
        }

        let old_secret: [u8; 32] = decode_fixed(&payload.old_note.secret, "old_note.secret")?;
        let old_salt: [u8; 16] = decode_fixed(&payload.old_note.salt, "old_note.salt")?;
        let old_note = Note::new(
            payload.subject.clone(),
            payload.old_note.owner_ot_addr,
            payload.old_note.amount,
            old_secret,
            old_salt,
        )?;
        let old_nullifier = old_note.nullifier(NULLIFIER_CTX);

        // 双花检查（锚定前查；并发窗口由 nullifiers PK + 锚定幂等兜底）。
        if deps.ledger.is_nullifier_spent(&old_nullifier).await? {
            return Err(DomainError::PolicyViolated(
                "nullifier 已花费（双花）".into(),
            ));
        }

        // crypto 前置校验（纯读，无随机性）：坏点在进审批门前即拒——
        // 否则首跑停门、approve 续跑才发现坏输入，浪费一次人工审批。
        let meta_view =
            crypto::StealthMetaAddressView::try_from(&payload.recipient_meta.into_meta())
                .map_err(|e| DomainError::InvalidInput(format!("接收方元地址非法：{e}")))?;
        let regulator_pub = crypto::stealth::decompress(&payload.regulator_view_pub)
            .map_err(|e| DomainError::InvalidInput(format!("监管 ViewKey 公钥非法：{e}")))?;

        // ---- L3 审批门：未决策即停（门内零业务写入，见模块 doc）----
        let row = deps.approvals.find(tx, &intent.id).await?;
        if row.as_ref().is_none_or(|r| r.is_undecided()) {
            if intent.status == IntentStatus::Authorized {
                intent.advance(IntentStatus::PolicyChecked)?;
            }
            return Ok(HandlerOutcome::AwaitingApproval {
                required_role: "regulator".into(),
            });
        }

        // ---- 审批通过后的后半程（approve 续跑从 PolicyChecked 起步）----
        if intent.status == IntentStatus::PolicyChecked {
            intent.advance(IntentStatus::ProofRequired)?;
            intent.advance(IntentStatus::Proved)?;
        }

        // crypto：随机 r 派生一次性地址（随机性只发生在通过审批的
        // committed 半程——首跑若在此前派生，approve 续跑会得到不同 OT）。
        let (ot, _shared) = crypto::derive_one_time(&meta_view)
            .map_err(|e| DomainError::InvalidInput(format!("一次性地址派生失败：{e}")))?;

        // 新 Note：secret/salt 由发送方生成，接收方经扫描 + 私库获取。
        let mut new_secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut new_secret);
        let mut new_salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut new_salt);
        let new_note = Note::new(
            payload.subject.clone(),
            ot.addr_digest(),
            payload.amount,
            new_secret,
            new_salt,
        )?;
        let new_commitment = new_note.commitment(deps.hasher.as_ref());

        // ExtraData：监管 ViewKey 加密（from/to/资产/时间仅进密文）。
        let extra_plain = serde_json::json!({
            "from": payload.from_did.as_str(),
            "to": payload.to_did.as_str(),
            "asset": subject_label(&payload.subject),
            "ts": now.to_rfc3339(),
        });
        let extra = crypto::ecies::encrypt_to(&regulator_pub, extra_plain.to_string().as_bytes())
            .map_err(|e| DomainError::InvalidInput(format!("ExtraData 加密失败：{e}")))?;

        // ZK 证明（note_opening@1：witness = 6 前像词，publics = C 的 8 limb）。
        let spec = CircuitSpec {
            id: "note_opening".into(),
            version: 1,
            public_inputs: commitment_limbs(&new_commitment),
        };
        let witness = vg_domain::ports::Witness {
            secrets: new_note
                .commitment_parts()
                .into_iter()
                .map(FieldElement::from_bytes)
                .collect(),
        };
        let bundle = deps.prover.prove(&spec, &witness).await?;
        if !deps.prover.verify(&bundle)? {
            return Err(DomainError::InvalidInput("证明验证失败".into()));
        }
        let proof_id = ProofId::new(format!("pf:{}", intent.id.as_ref()));
        deps.proofs
            .save(
                tx,
                &ProofRecord {
                    proof_id: proof_id.as_ref().to_string(),
                    circuit_id: bundle.circuit_id.clone(),
                    circuit_version: bundle.version as i64,
                    statement_hash: new_commitment,
                    proof: bundle.proof.clone(),
                    publics: bundle.publics.clone(),
                    verified: true,
                },
            )
            .await?;

        // ---- 三表写入（同事务；engine savepoint 保护）----
        sqlx::query(
            "INSERT INTO notes \
                 (commitment, asset_ref, owner_ot_addr, amount, created_tx, \
                  addr_point, ephemeral, secret, salt) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(new_commitment.as_bytes().as_slice())
        .bind(subject_label(&payload.subject))
        .bind(new_note.owner_ot_addr().as_bytes().as_slice())
        .bind(new_note.amount() as i64)
        .bind(intent.id.as_ref())
        .bind(ot.addr_point.as_bytes().as_slice())
        .bind(ot.ephemeral.as_bytes().as_slice())
        .bind(new_note.secret().as_slice())
        .bind(new_note.salt().as_slice())
        .execute(&mut **tx)
        .await
        .map_err(storage_err)?;

        sqlx::query(
            "INSERT INTO nullifiers (nf, spent_at, intent_id) VALUES ($1, $2, $3)",
        )
        .bind(old_nullifier.as_bytes().as_slice())
        .bind(now)
        .bind(intent.id.as_ref())
        .execute(&mut **tx)
        .await
        .map_err(storage_err)?;

        sqlx::query(
            "INSERT INTO shielded_txs (nf, commitment, extra, at) VALUES ($1, $2, $3, $4)",
        )
        .bind(old_nullifier.as_bytes().as_slice())
        .bind(new_commitment.as_bytes().as_slice())
        .bind(extra.as_slice())
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(storage_err)?;

        // 不发领域事件（隐私语义，见模块 doc）。

        // ---- 悬挂锚契约：最后锚定，顺序 Nullifier → Commitment → Extra ----
        deps.ledger
            .anchor(LedgerItem::Nullifier(old_nullifier))
            .await?;
        deps.ledger
            .anchor(LedgerItem::Commitment(new_commitment))
            .await?;
        deps.ledger
            .anchor(LedgerItem::EncryptedExtra(extra))
            .await?;

        Ok(HandlerOutcome::Completed {
            result_ref: new_commitment.as_hex(),
            resource: subject_label(&payload.subject),
            policy: vec![],
            proof_id: Some(proof_id),
        })
    }
}

/// 承诺 → note_opening 公开输入（C 的 8 个小端 u32 limb，各低 4 字节 LE）。
///
/// 与 vg-infra-zk dispatcher 的映射表口径一致：Poseidon2 挤出的 8 个
/// canonical u32 小端拼接即承诺字节，按 4 字节重切还原 limb。
fn commitment_limbs(commitment: &Hash32) -> Vec<FieldElement> {
    commitment
        .as_bytes()
        .chunks_exact(4)
        .map(|c| {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(c);
            FieldElement::from_bytes(b)
        })
        .collect()
}

/// sqlx 错误 → 领域存储错误（handler 直写隐私表的唯一 SQL 面）。
fn storage_err(e: sqlx::Error) -> DomainError {
    DomainError::Storage(format!("隐私表写入失败：{e}"))
}

#[cfg(test)]
mod tests {
    //! Task 21 e2e 测试（sqlx::test）：真实 crypto / PoseidonNoteHasher /
    //! ProverDispatcher（note_opening 实电路证明，~0.14s/次）+ InProcessLedger。
    //!
    //! 覆盖：完整隐匿转移（审批门→Confirmed→三表/证明/锚定/审计）→
    //! 接收方扫描命中 → 第三方视角无 from/to → 监管解密 → 双花拒绝 →
    //! 坏元地址拒绝 → validium root 幂等与 merkle 正确性 → IAM 授权刷新。

    use super::*;
    use std::sync::Arc;

    use vg_domain::identity::ports::IdentityRepository;
    use vg_domain::identity::{
        Capability, DidDocument, KeyType, SubjectKind, VerificationMethod,
    };
    use crate::intent_engine::RawIntent;
    use vg_domain::shared::{Did, IntentId};
    use vg_infra_crypto::{KeyPair, PoseidonNoteHasher};
    use vg_infra_pg::{
        InProcessLedger, PgApprovalsStore, PgAuditWriter, PgCommodityRepo, PgCredentialRepo,
        PgIdentityRepo, PgIntentRepository, PgLifecycleRepo, PgOutbox, PgOwnershipRepo,
        PgPolicyRepository, PgProofStore,
    };
    use vg_infra_zk::ProverDispatcher;

    use crate::deps::AppDeps as Deps;
    use crate::intent_engine::{HandlerMap, IntentEngine};
    use crate::services;

    // ---- fixture ----

    fn did(s: &str) -> Did {
        Did::parse(s).unwrap()
    }

    fn doc(did: Did, kind: SubjectKind) -> DidDocument {
        DidDocument {
            did: did.clone(),
            kind,
            methods: vec![VerificationMethod::new(
                "k-0",
                KeyType::Secp256k1,
                Hash32::keccak(b"pk"),
                did,
            )],
            parent: None,
            jurisdiction: Some("CN".into()),
            created_at: Utc::now(),
        }
    }

    /// 真实组件装配：PoseidonNoteHasher + ProverDispatcher + InProcessLedger。
    fn deps(pool: sqlx::PgPool) -> Deps {
        Deps {
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
            prover: Arc::new(ProverDispatcher),
            hasher: Arc::new(PoseidonNoteHasher),
        }
    }

    fn engine(pool: sqlx::PgPool) -> IntentEngine {
        let mut map = HandlerMap::new();
        crate::handlers::register_default(&mut map);
        IntentEngine::new(deps(pool), map)
    }

    /// 三方密钥 fixture：发送方 / 接收方（view+spend）/ 监管（view）。
    struct Parties {
        sender_did: Did,
        recipient_did: Did,
        regulator_did: Did,
        recipient_meta: StealthMetaAddress,
        view_priv_hex: String,
        spend_pub_hex: String,
        reg_view_priv_hex: String,
        reg_view_pub_hex: String,
    }

    /// 身份铺设：发送方（企业 + SubmitShieldedTx）、接收方、监管方文档。
    async fn seed_parties(pool: &sqlx::PgPool) -> Parties {
        let sender_kp = KeyPair::generate();
        let sender_did = did(&vg_infra_crypto::pubkey_to_did(sender_kp.public()));
        let recipient_did = did("did:vg:user:retailer-shielded");
        let regulator_did = did("did:vg:user:reg-shielded");

        let view_kp = KeyPair::generate();
        let spend_kp = KeyPair::generate();
        let reg_kp = KeyPair::generate();
        let meta_view =
            crypto::StealthMetaAddressView::from_keys(view_kp.public(), spend_kp.public());

        let mut tx = pool.begin().await.unwrap();
        let identity = PgIdentityRepo;
        identity
            .save_document(&mut tx, &doc(sender_did.clone(), SubjectKind::Enterprise))
            .await
            .unwrap();
        identity
            .save_document(&mut tx, &doc(recipient_did.clone(), SubjectKind::Enterprise))
            .await
            .unwrap();
        identity
            .save_document(&mut tx, &doc(regulator_did.clone(), SubjectKind::Regulator))
            .await
            .unwrap();
        let grantor = did("did:vg:user:grantor-t21");
        identity
            .save_document(&mut tx, &doc(grantor.clone(), SubjectKind::Enterprise))
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

        Parties {
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

    /// 旧 Note 直接裸 SQL seed（含 0007 全部新列；发送方自持有）。
    async fn seed_old_note(pool: &sqlx::PgPool, subject: &SubjectRef, amount: u64) -> OldNoteSpec {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        secret[0] |= 0x80; // 保证非全零（OsRng 全零概率不可达，防御式）
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let owner = Hash32::keccak(b"old-owner-ot");
        let note = Note::new(subject.clone(), owner, amount, secret, salt).unwrap();
        let commitment = note.commitment(&PoseidonNoteHasher);
        // 扫描公布值：旧 Note 归发送方本地，占位列用任意合法压缩点
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

    fn shielded_payload(p: &Parties, subject: &SubjectRef, old: &OldNoteSpec) -> serde_json::Value {
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

    fn raw(id: &str, actor: &Did, payload: serde_json::Value, nonce: u64) -> RawIntent {
        RawIntent {
            id: IntentId::new(id),
            action: vg_domain::intent::IntentAction::ShieldedTransfer,
            actor: actor.clone(),
            on_behalf_of: None,
            payload,
            nonce,
            expires_at: Utc::now() + chrono::Duration::hours(1),
        }
    }

    // ---- 测试 ----

    /// e2e 隐匿转移：停门 → 审批 → Confirmed；三表/证明/锚定/审计全断言。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn shielded_transfer_e2e(pool: sqlx::PgPool) {
        let p = seed_parties(&pool).await;
        let subject = SubjectRef::Batch(vg_domain::shared::BatchId::new("bt-shield-1"));
        let old = seed_old_note(&pool, &subject, 10).await;
        let eng = engine(pool.clone());

        // 首跑：停在 L3 审批门（零业务写入）
        let r1 = eng
            .execute(raw("st-1", &p.sender_did, shielded_payload(&p, &subject, &old), 1))
            .await
            .unwrap();
        assert_eq!(r1.status, IntentStatus::PolicyChecked);
        assert!(r1.awaiting_approval);
        let notes_before: (i64,) = sqlx::query_as("SELECT count(*) FROM notes")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(notes_before.0, 1, "门内不得产生新 Note 行");
        let row = PgApprovalsStore
            .find(&mut pool.begin().await.unwrap(), &IntentId::new("st-1"))
            .await
            .unwrap()
            .expect("审批行应存在");
        assert!(row.is_undecided());
        assert_eq!(row.required_role, "regulator");

        // 审批续跑 → Confirmed
        let r2 = eng
            .approve(&IntentId::new("st-1"), &p.regulator_did)
            .await
            .unwrap();
        assert_eq!(r2.status, IntentStatus::Confirmed);
        let commitment_hex = r2.result_ref.clone().unwrap();
        assert_eq!(commitment_hex.len(), 64);

        // notes 新行：33B 两列 / 金额 / created_tx
        let note_row: (String, i64, i32, i32) = sqlx::query_as(
            "SELECT encode(owner_ot_addr, 'hex'), amount, \
                    octet_length(addr_point), octet_length(ephemeral) \
             FROM notes WHERE commitment = decode($1, 'hex')",
        )
        .bind(&commitment_hex)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(note_row.1, 10);
        assert_eq!(note_row.2, 33);
        assert_eq!(note_row.3, 33);
        let created_tx: (String,) = sqlx::query_as(
            "SELECT created_tx FROM notes WHERE commitment = decode($1, 'hex')",
        )
        .bind(&commitment_hex)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(created_tx.0, "st-1");

        // nullifiers / shielded_txs（extra 非空）
        let nf_count: (i64,) =
            sqlx::query_as("SELECT count(*) FROM nullifiers WHERE intent_id = 'st-1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(nf_count.0, 1);
        let tx_row: (i32,) = sqlx::query_as(
            "SELECT octet_length(extra) FROM shielded_txs \
             WHERE commitment = decode($1, 'hex')",
        )
        .bind(&commitment_hex)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(tx_row.0 > 0, "ExtraData 密文非空");

        // proofs：note_opening 且 verified
        let proof_row: (String, bool) = sqlx::query_as(
            "SELECT circuit_id, verified FROM proofs WHERE proof_id = 'pf:st-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(proof_row.0, "note_opening");
        assert!(proof_row.1);

        // ledger_anchors：三种 kind 各 1 条
        for kind in ["nullifier", "commitment", "encrypted_extra"] {
            let c: (i64,) = sqlx::query_as("SELECT count(*) FROM ledger_anchors WHERE kind = $1")
                .bind(kind)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(c.0, 1, "kind={kind}");
        }

        // audit allow 行
        let audit: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM audit_events WHERE intent_id = 'st-1' AND result = 'allow'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit.0, 1);

        // 不发领域事件（隐私取舍，见 handler doc）
        let events: (i64,) = sqlx::query_as("SELECT count(*) FROM domain_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(events.0, 0);

        // ---- 接收方可扫到（恰一张，t 非空）----
        let scanned = services::shielded::scan_notes(
            &deps(pool.clone()),
            &p.view_priv_hex,
            &p.spend_pub_hex,
        )
        .await
        .unwrap();
        assert!(
            scanned.len() == 1,
            "接收方扫描应恰命中新 Note（旧 Note 属发送方），实际 {}",
            scanned.len()
        );
        assert_eq!(scanned[0].commitment, commitment_hex);
        assert_eq!(scanned[0].amount, 10);
        assert_eq!(scanned[0].t.len(), 64, "t 为 32 字节 hex");
        assert_eq!(scanned[0].asset_ref, "batch:bt-shield-1");

        // 第三方视角：三表全文无 from/to DID 字符串
        for table in ["notes", "shielded_txs", "ledger_anchors"] {
            let q = format!("SELECT t::text AS s FROM {table} t");
            let rows: Vec<(String,)> = sqlx::query_as(&q).fetch_all(&pool).await.unwrap();
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

        // ---- 监管可解 ----
        let extra: (Vec<u8>,) = sqlx::query_as(
            "SELECT extra FROM shielded_txs WHERE commitment = decode($1, 'hex')",
        )
        .bind(&commitment_hex)
        .fetch_one(&pool)
        .await
        .unwrap();
        let plain =
            services::shielded::regulator_decrypt(&extra.0, &p.reg_view_priv_hex).unwrap();
        assert_eq!(plain["from"], serde_json::json!(p.sender_did.as_str()));
        assert_eq!(plain["to"], serde_json::json!(p.recipient_did.as_str()));
        assert_eq!(plain["asset"], serde_json::json!("batch:bt-shield-1"));
        assert!(plain["ts"].is_string());
    }

    /// 双花（plan 必测）：同 old_note 第二次提交 → Rejected 含双花提示，
    /// notes 行数不变。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn double_spend_rejected(pool: sqlx::PgPool) {
        let p = seed_parties(&pool).await;
        let subject = SubjectRef::Batch(vg_domain::shared::BatchId::new("bt-shield-2"));
        let old = seed_old_note(&pool, &subject, 5).await;
        let eng = engine(pool.clone());
        let payload = shielded_payload(&p, &subject, &old);

        eng.execute(raw("ds-1", &p.sender_did, payload.clone(), 1))
            .await
            .unwrap();
        let confirmed = eng
            .approve(&IntentId::new("ds-1"), &p.regulator_did)
            .await
            .unwrap();
        assert_eq!(confirmed.status, IntentStatus::Confirmed);

        let before: (i64,) = sqlx::query_as("SELECT count(*) FROM notes")
            .fetch_one(&pool)
            .await
            .unwrap();

        let r2 = eng
            .execute(raw("ds-2", &p.sender_did, payload, 2))
            .await
            .unwrap();
        assert_eq!(r2.status, IntentStatus::Rejected);
        assert!(
            r2.rejection.as_deref().is_some_and(|x| x.contains("双花")),
            "实际：{:?}",
            r2.rejection
        );
        let after: (i64,) = sqlx::query_as("SELECT count(*) FROM notes")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(after.0, before.0, "双花拒绝不得产生新 Note");
    }

    /// 坏 recipient_meta（前缀合法但不在曲线上）→ Rejected。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn bad_recipient_meta_rejected(pool: sqlx::PgPool) {
        let p = seed_parties(&pool).await;
        let subject = SubjectRef::Batch(vg_domain::shared::BatchId::new("bt-shield-3"));
        let old = seed_old_note(&pool, &subject, 7).await;
        let eng = engine(pool.clone());

        // 确定性寻找前缀 02 但不在曲线上的坏点（至多 20 次变形，必有一个）
        let mut bad_hex = String::new();
        for i in 0..20 {
            let mut bad = [0x02u8; 33];
            bad[5 + i] = (i as u8).wrapping_mul(37) | 1;
            let cp = CompressedPoint::new(bad).unwrap();
            if crypto::stealth::decompress(&cp).is_err() {
                bad_hex = cp.as_hex();
                break;
            }
        }
        assert!(!bad_hex.is_empty(), "20 次变形应存在非曲线点");

        let mut payload = shielded_payload(&p, &subject, &old);
        payload["recipient_meta"]["view_pub"] = serde_json::json!(bad_hex);
        let r = eng
            .execute(raw("bm-1", &p.sender_did, payload, 1))
            .await
            .unwrap();
        assert_eq!(r.status, IntentStatus::Rejected);
        assert!(
            r.rejection
                .as_deref()
                .is_some_and(|x| x.contains("元地址非法")),
            "实际：{:?}",
            r.rejection
        );
    }

    /// 金额不符（非全额）→ Rejected。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn partial_amount_rejected(pool: sqlx::PgPool) {
        let p = seed_parties(&pool).await;
        let subject = SubjectRef::Batch(vg_domain::shared::BatchId::new("bt-shield-4"));
        let old = seed_old_note(&pool, &subject, 9).await;
        let eng = engine(pool);
        let mut payload = shielded_payload(&p, &subject, &old);
        payload["amount"] = serde_json::json!(3);
        let r = eng
            .execute(raw("pa-1", &p.sender_did, payload, 1))
            .await
            .unwrap();
        assert_eq!(r.status, IntentStatus::Rejected);
        assert!(
            r.rejection
                .as_deref()
                .is_some_and(|x| x.contains("全额转移"))
        );
    }

    /// 扫描不命中：他人 view 私钥扫不出任何 Note。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn scan_with_wrong_view_key_finds_nothing(pool: sqlx::PgPool) {
        let p = seed_parties(&pool).await;
        let subject = SubjectRef::Batch(vg_domain::shared::BatchId::new("bt-shield-5"));
        let old = seed_old_note(&pool, &subject, 4).await;
        let eng = engine(pool.clone());
        eng.execute(raw(
            "sv-1",
            &p.sender_did,
            shielded_payload(&p, &subject, &old),
            1,
        ))
        .await
        .unwrap();
        eng.approve(&IntentId::new("sv-1"), &p.regulator_did)
            .await
            .unwrap();

        let wrong_view = KeyPair::generate();
        let scanned = services::shielded::scan_notes(
            &deps(pool),
            &hex::encode(wrong_view.secret().to_bytes()),
            &p.spend_pub_hex,
        )
        .await
        .unwrap();
        assert!(scanned.is_empty());
    }

    /// validium root 幂等（plan 必测）：同 batch_ref 两次提交同根返回、
    /// 库 1 行、ledger_anchors 各记 2 条 state_root；merkle 手算比对。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn validium_root_idempotent_and_merkle_correct(pool: sqlx::PgPool) {
        let d = deps(pool.clone());
        let h1 = Hash32::keccak(b"item-1");
        let h2 = Hash32::keccak(b"item-2");
        let h3 = Hash32::keccak(b"item-3");

        // 手算 3 叶（奇数补末）：h12=keccak(h1‖h2)，h33=keccak(h3‖h3)
        let pair = |a: &Hash32, b: &Hash32| {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(a.as_bytes());
            buf[32..].copy_from_slice(b.as_bytes());
            Hash32::keccak(&buf)
        };
        let expect = pair(&pair(&h1, &h2), &pair(&h3, &h3));
        assert_eq!(services::validium::merkle_root(&[h1, h2, h3]), expect);
        // 空 → 零根；单叶 → 叶本身
        assert_eq!(services::validium::merkle_root(&[]), Hash32::ZERO);
        assert_eq!(services::validium::merkle_root(&[h1]), h1);

        let r1 = services::validium::submit_validium_root(&d, "br-1", &[h1, h2, h3])
            .await
            .unwrap();
        let r2 = services::validium::submit_validium_root(&d, "br-1", &[h1, h2, h3])
            .await
            .unwrap();
        assert_eq!(r1, expect);
        assert_eq!(r1, r2, "幂等：同 batch_ref 二次提交返回既有根");

        let rows: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM validium_batches WHERE batch_ref = 'br-1'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rows.0, 1, "库不重复");
        let anchors: (i64,) =
            sqlx::query_as("SELECT count(*) FROM ledger_anchors WHERE kind = 'state_root'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(anchors.0, 2, "账本每次提交各锚一次（Task 18 口径）");

        // 幂等 + 不同条目：仍返回首批根（结果不可改写）
        let r3 = services::validium::submit_validium_root(&d, "br-1", &[h1])
            .await
            .unwrap();
        assert_eq!(r3, expect);
    }

    /// IAM 授权：写入 + 刷新 until。
    #[sqlx::test(migrations = "../vg-infra-pg/migrations")]
    async fn grant_data_access_upserts(pool: sqlx::PgPool) {
        let d = deps(pool.clone());
        let regulator = did("did:vg:user:reg-iam");
        let t1 = Utc::now() + chrono::Duration::days(1);
        let t2 = t1 + chrono::Duration::days(30);

        services::validium::grant_data_access(&d, &regulator, "coldchain:cn-2026", t1)
            .await
            .unwrap();
        let stored = services::validium::data_access_until(&d, &regulator, "coldchain:cn-2026")
            .await
            .unwrap()
            .expect("授权行应存在");
        // PG timestamptz 微秒精度：纳秒截断内视为相等
        assert!((stored - t1).abs() < chrono::Duration::milliseconds(1));

        // 刷新语义：覆盖 until
        services::validium::grant_data_access(&d, &regulator, "coldchain:cn-2026", t2)
            .await
            .unwrap();
        let refreshed =
            services::validium::data_access_until(&d, &regulator, "coldchain:cn-2026")
                .await
                .unwrap()
                .expect("授权行应存在");
        assert!((refreshed - t2).abs() < chrono::Duration::milliseconds(1));
        assert!(refreshed > stored, "刷新后截止时刻应延后");
        let rows: (i64,) =
            sqlx::query_as("SELECT count(*) FROM data_access_grants WHERE grantee = $1")
                .bind(regulator.as_str())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(rows.0, 1, "upsert 不产生重复行");
    }
}
