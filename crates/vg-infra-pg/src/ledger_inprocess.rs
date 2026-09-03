//! InProcessLedger：模拟 Polygon CDK 账本的默认 [`LedgerPort`] 实现（Task 18）。
//!
//! Phase1 默认账本：不触链，锚定写入 `ledger_anchors`，链式状态根存于
//! `ledger_state` 单行表（0005 迁移）。Task 26 alloy 实装真实链层前的
//! 过渡实现——端口语义（幂等、双花检查）与真实实现保持一致。
//!
//! ## ref_hash 口径（写死，测试锁定）
//!
//! | LedgerItem 变体 | ref_hash |
//! |---|---|
//! | Commitment(h) / Nullifier(h) | h 本身（32 字节） |
//! | 其余 5 变体 | keccak256(serde_json 相邻标签规范 JSON 字节)，即 `serde_json::to_vec(item)` |
//!
//! ## kind 映射（写死，与 0001 CHECK 白名单一致）
//!
//! Commitment→commitment、Nullifier→nullifier、EncryptedExtra→encrypted_extra、
//! Transfer→transfer、CredentialStatus→credential_status、
//! LifecycleChange→lifecycle_change、PolicyRegistered→policy_registered；
//! submit_state_root→state_root。
//!
//! ## root 链式语义
//!
//! 每成功锚定一条：`root' = keccak(root ‖ ref_hash)`，`seq += 1`，
//! 回执 `tx_ref = "inprocess:<seq>"`、`in_process = true`。初始 root 为
//! 32 字节全零。commitment/nullifier 重复锚定走幂等分支（返回已有回执，
//! **不推进链**）；其余 kind（含 state_root，无唯一索引）每次各自记账、
//! 各推进一次链。

use async_trait::async_trait;
use sqlx::Row;
use vg_domain::ports::{AnchorReceipt, LedgerItem, LedgerPort};
use vg_domain::shared::{DomainError, Hash32};

/// 模拟 CDK 账本（服务型端口：自管连接/事务，无 Context）。
#[derive(Debug, Clone)]
pub struct InProcessLedger {
    pool: sqlx::PgPool,
}

impl InProcessLedger {
    /// 由共享连接池构造。
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// 当前链根（测试 / 对账用；生产对账走 submit_state_root 语义）。
    pub async fn current_root(&self) -> Result<Hash32, DomainError> {
        let row = sqlx::query("SELECT root FROM ledger_state WHERE id = 1")
            .fetch_one(&self.pool)
            .await
            .map_err(crate::storage)?;
        hash32_from_db(row.get("root"), "ledger_state.root")
    }

    /// 当前已锚定序号（测试用，与 [`Self::current_root`] 配套）。
    pub async fn current_seq(&self) -> Result<i64, DomainError> {
        let row = sqlx::query("SELECT seq FROM ledger_state WHERE id = 1")
            .fetch_one(&self.pool)
            .await
            .map_err(crate::storage)?;
        Ok(row.get("seq"))
    }

    /// 锚定核心流程（anchor / submit_state_root 共用）。
    ///
    /// 事务顺序（幂等不推链、推链必成功回填）：
    /// 1. `INSERT ... ON CONFLICT DO NOTHING RETURNING id`（tx_ref 暂为占位空串）；
    /// 2. 0 行（仅 commitment/nullifier 可能）→ SELECT 已存在行的
    ///    tx_ref/anchored_at 返回其回执——**幂等：不推进链**；
    /// 3. 1 行 → `SELECT ... FOR UPDATE` 锁 ledger_state 单行取前根 →
    ///    `UPDATE ledger_state SET root = keccak(前根 ‖ ref_hash), seq = seq+1
    ///    RETURNING seq`（行锁串行化并发链推进）→ 按 bigserial `id` 回填
    ///    新行的 `tx_ref = "inprocess:<seq>"` → 返回回执。
    async fn anchor_inner(
        &self,
        kind: &str,
        ref_hash: &Hash32,
        payload: serde_json::Value,
    ) -> Result<AnchorReceipt, DomainError> {
        let payload_text = serde_json::to_string(&payload)
            .map_err(|e| DomainError::Storage(format!("payload 序列化失败：{e}")))?;

        let mut tx = self.pool.begin().await.map_err(crate::storage)?;

        // (1) 尝试插入；commitment/nullifier 命中部分唯一索引时 0 行
        let inserted = sqlx::query(
            "INSERT INTO ledger_anchors \
                 (kind, ref_hash, payload, tx_ref, status, created_at, anchored_at) \
             VALUES ($1, $2, $3::jsonb, '', 'anchored', now(), now()) \
             ON CONFLICT DO NOTHING \
             RETURNING id",
        )
        .bind(kind)
        .bind(ref_hash.as_bytes().as_slice())
        .bind(&payload_text)
        .fetch_optional(&mut *tx)
        .await
        .map_err(crate::storage)?;

        let row_id: i64 = match inserted {
            // (2) 幂等分支：读已有行回执，不推进链
            None => {
                let existing = sqlx::query(
                    "SELECT tx_ref, anchored_at FROM ledger_anchors \
                     WHERE kind = $1 AND ref_hash = $2 AND status = 'anchored'",
                )
                .bind(kind)
                .bind(ref_hash.as_bytes().as_slice())
                .fetch_one(&mut *tx)
                .await
                .map_err(crate::storage)?;
                let receipt = AnchorReceipt {
                    tx_ref: existing.get("tx_ref"),
                    anchored_at: existing.get("anchored_at"),
                    in_process: true,
                };
                tx.commit().await.map_err(crate::storage)?;
                return Ok(receipt);
            }
            // (3) 新插入行：推链并回填 tx_ref
            Some(row) => row.get("id"),
        };

        // 推链：FOR UPDATE 锁单行取前根，串行化并发推进
        let prev_row = sqlx::query("SELECT root FROM ledger_state WHERE id = 1 FOR UPDATE")
            .fetch_one(&mut *tx)
            .await
            .map_err(crate::storage)?;
        let prev_root = hash32_from_db(prev_row.get("root"), "ledger_state.root")?;
        let mut chained = [0u8; 64];
        chained[..32].copy_from_slice(prev_root.as_bytes());
        chained[32..].copy_from_slice(ref_hash.as_bytes());
        let new_root = Hash32::keccak(&chained);

        let state_row = sqlx::query(
            "UPDATE ledger_state SET root = $1, seq = seq + 1 WHERE id = 1 RETURNING seq",
        )
        .bind(new_root.as_bytes().as_slice())
        .fetch_one(&mut *tx)
        .await
        .map_err(crate::storage)?;
        let seq: i64 = state_row.get("seq");

        // 回填 tx_ref（bigserial PK 定位；seq 为 bigint，恒非负，无符号还原）
        let receipt = sqlx::query(
            "UPDATE ledger_anchors SET tx_ref = $1 WHERE id = $2 RETURNING anchored_at",
        )
        .bind(format!("inprocess:{seq}"))
        .bind(row_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(crate::storage)?;
        let anchored_at: chrono::DateTime<chrono::Utc> = receipt.get("anchored_at");

        tx.commit().await.map_err(crate::storage)?;
        Ok(AnchorReceipt {
            tx_ref: format!("inprocess:{seq}"),
            anchored_at,
            in_process: true,
        })
    }
}

/// bytea → [`Hash32`]；长度非 32 说明存储层数据损坏。
fn hash32_from_db(bytes: Vec<u8>, field: &str) -> Result<Hash32, DomainError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DomainError::Storage(format!("库中 {field} 长度非法")))?;
    Ok(Hash32::from_bytes(arr))
}

/// kind 映射（见模块文档口径表）。
fn kind_of(item: &LedgerItem) -> &'static str {
    match item {
        LedgerItem::Commitment(_) => "commitment",
        LedgerItem::Nullifier(_) => "nullifier",
        LedgerItem::EncryptedExtra(_) => "encrypted_extra",
        LedgerItem::Transfer { .. } => "transfer",
        LedgerItem::CredentialStatus { .. } => "credential_status",
        LedgerItem::LifecycleChange { .. } => "lifecycle_change",
        LedgerItem::PolicyRegistered { .. } => "policy_registered",
    }
}

/// ref_hash 口径（见模块文档口径表）。
fn ref_hash_of(item: &LedgerItem) -> Result<Hash32, DomainError> {
    match item {
        LedgerItem::Commitment(h) | LedgerItem::Nullifier(h) => Ok(*h),
        // 其余变体：相邻标签规范 JSON 字节的 keccak256
        other => {
            let bytes = serde_json::to_vec(other)
                .map_err(|e| DomainError::Storage(format!("LedgerItem 序列化失败：{e}")))?;
            Ok(Hash32::keccak(&bytes))
        }
    }
}

#[async_trait]
impl LedgerPort for InProcessLedger {
    async fn anchor(&self, item: LedgerItem) -> Result<AnchorReceipt, DomainError> {
        let kind = kind_of(&item);
        let ref_hash = ref_hash_of(&item)?;
        let payload = serde_json::to_value(&item)
            .map_err(|e| DomainError::Storage(format!("payload 序列化失败：{e}")))?;
        self.anchor_inner(kind, &ref_hash, payload).await
    }

    /// 提交状态根：kind='state_root'、ref_hash=root 本身、payload 含
    /// batch_ref。**无唯一索引，重复提交各自记账、各推一次链**（与
    /// commitment/nullifier 的幂等语义不同——状态根按批次结算，重提交
    /// 即重记账，doc 注明区别）。
    async fn submit_state_root(
        &self,
        root: Hash32,
        batch_ref: &str,
    ) -> Result<AnchorReceipt, DomainError> {
        let payload = serde_json::json!({ "batch_ref": batch_ref });
        self.anchor_inner("state_root", &root, payload).await
    }

    async fn is_nullifier_spent(&self, n: &Hash32) -> Result<bool, DomainError> {
        let row = sqlx::query(
            "SELECT EXISTS( \
                 SELECT 1 FROM ledger_anchors \
                 WHERE kind = 'nullifier' AND ref_hash = $1) AS spent",
        )
        .bind(n.as_bytes().as_slice())
        .fetch_one(&self.pool)
        .await
        .map_err(crate::storage)?;
        Ok(row.get("spent"))
    }

    async fn is_commitment_present(&self, c: &Hash32) -> Result<bool, DomainError> {
        let row = sqlx::query(
            "SELECT EXISTS( \
                 SELECT 1 FROM ledger_anchors \
                 WHERE kind = 'commitment' AND ref_hash = $1) AS present",
        )
        .bind(c.as_bytes().as_slice())
        .fetch_one(&self.pool)
        .await
        .map_err(crate::storage)?;
        Ok(row.get("present"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use vg_domain::credential::CredStatus;
    use vg_domain::lifecycle::LifecycleState;
    use vg_domain::shared::{AssetId, BatchId, CredentialId, Did, PolicyId, SubjectRef};

    fn did(s: &str) -> Did {
        Did::parse(s).unwrap()
    }

    /// 测试用 item 样本（与领域 ports 测试同构，各变体一份）。
    fn sample_items() -> Vec<LedgerItem> {
        let h = Hash32::keccak(b"x");
        vec![
            LedgerItem::Commitment(h),
            LedgerItem::Nullifier(h),
            LedgerItem::EncryptedExtra(vec![1, 2, 3]),
            LedgerItem::Transfer {
                subject: SubjectRef::Batch(BatchId::new("b1")),
                from: did("did:vg:user:alice"),
                to: did("did:vg:user:bob"),
                c2c: true,
            },
            LedgerItem::CredentialStatus {
                id: CredentialId::new("c1"),
                hash: h,
                status: CredStatus::Revoked,
            },
            LedgerItem::LifecycleChange {
                subject: SubjectRef::Asset(AssetId::new("a1")),
                from: LifecycleState::Produced,
                to: LifecycleState::InTransit,
            },
            LedgerItem::PolicyRegistered {
                id: PolicyId::new("p1"),
                version: 3,
                hash: h,
            },
        ]
    }

    /// nullifier 二次 anchor 幂等（plan 必测）：同 tx_ref、seq 不变、
    /// 双花检查为真；再锚另一 item 验证链只推进一步。
    #[sqlx::test]
    async fn nullifier_reanchor_is_idempotent(pool: sqlx::PgPool) {
        let ledger = InProcessLedger::new(pool);
        let n1 = Hash32::keccak(b"n1");

        let r1 = ledger
            .anchor(LedgerItem::Nullifier(n1))
            .await
            .expect("首次锚定应成功");
        assert_eq!(r1.tx_ref, "inprocess:1");
        assert!(r1.in_process);
        assert!(ledger.is_nullifier_spent(&n1).await.unwrap());

        // 二次锚定：返回同一回执（tx_ref 一致），链不重复推进
        let r2 = ledger
            .anchor(LedgerItem::Nullifier(n1))
            .await
            .expect("幂等重锚应成功");
        assert_eq!(r2.tx_ref, r1.tx_ref, "幂等重锚应返回同一 tx_ref");
        assert!(r2.in_process);
        assert_eq!(ledger.current_seq().await.unwrap(), 1, "链未重复推进");

        // 锚另一 item：seq 只 +1（证明上一步未推链）
        let r3 = ledger
            .anchor(LedgerItem::Nullifier(Hash32::keccak(b"n2")))
            .await
            .unwrap();
        assert_eq!(r3.tx_ref, "inprocess:2");
        assert_eq!(ledger.current_seq().await.unwrap(), 2);
    }

    /// commitment 同款幂等 + 成员检查 true / 未锚定 false。
    #[sqlx::test]
    async fn commitment_idempotent_and_presence(pool: sqlx::PgPool) {
        let ledger = InProcessLedger::new(pool);
        let c1 = Hash32::keccak(b"c1");
        let absent = Hash32::keccak(b"absent");

        assert!(
            !ledger.is_commitment_present(&c1).await.unwrap(),
            "未锚定应 false"
        );
        let r1 = ledger.anchor(LedgerItem::Commitment(c1)).await.unwrap();
        assert!(ledger.is_commitment_present(&c1).await.unwrap());
        assert!(!ledger.is_commitment_present(&absent).await.unwrap());

        let r2 = ledger.anchor(LedgerItem::Commitment(c1)).await.unwrap();
        assert_eq!(r2.tx_ref, r1.tx_ref);
        assert_eq!(ledger.current_seq().await.unwrap(), 1);
    }

    /// root 单调演进（plan 必测）：[c1, n1, transfer] 每步变化，且与
    /// 手算 keccak(keccak(keccak(zero‖h1)‖h2)‖h3) 一致——commitment
    /// （h 本身）与 transfer（serde JSON keccak）口径混用正确。
    #[sqlx::test]
    async fn root_advances_monotonically_and_matches_hand_chain(pool: sqlx::PgPool) {
        let ledger = InProcessLedger::new(pool);
        assert_eq!(
            ledger.current_root().await.unwrap(),
            Hash32::ZERO,
            "初始为零根"
        );

        let c1 = Hash32::keccak(b"commit-1");
        let n1 = Hash32::keccak(b"null-1");
        let transfer = LedgerItem::Transfer {
            subject: SubjectRef::Batch(BatchId::new("b9")),
            from: did("did:vg:user:a"),
            to: did("did:vg:user:b"),
            c2c: false,
        };
        let transfer_ref = ref_hash_of(&transfer).unwrap();
        assert_ne!(
            transfer_ref, c1,
            "transfer 的 serde-JSON 口径应与 commitment 原值口径不同来源"
        );

        let items = [
            (LedgerItem::Commitment(c1), c1),
            (LedgerItem::Nullifier(n1), n1),
            (transfer.clone(), transfer_ref),
        ];

        // 手算链：root_{i+1} = keccak(root_i ‖ ref_hash_i)
        let mut hand = Hash32::ZERO;
        let mut prev_root = Hash32::ZERO;
        for (i, (item, ref_hash)) in items.iter().enumerate() {
            let receipt = ledger.anchor(item.clone()).await.unwrap();
            assert_eq!(receipt.tx_ref, format!("inprocess:{}", i + 1));

            let mut chained = [0u8; 64];
            chained[..32].copy_from_slice(hand.as_bytes());
            chained[32..].copy_from_slice(ref_hash.as_bytes());
            hand = Hash32::keccak(&chained);

            let current = ledger.current_root().await.unwrap();
            assert_eq!(current, hand, "第 {} 步链根应与手算一致", i + 1);
            assert_ne!(current, prev_root, "链根应单调变化");
            prev_root = current;
        }
    }

    /// submit_state_root：tx_ref 递增、payload 含 batch_ref、重复提交
    /// 各自成功（无幂等去重）且各推一次链。
    #[sqlx::test]
    async fn state_root_submissions_each_advance_chain(pool: sqlx::PgPool) {
        let ledger = InProcessLedger::new(pool);
        let root = Hash32::keccak(b"root-a");

        let r1 = ledger.submit_state_root(root, "batch-1").await.unwrap();
        let r2 = ledger.submit_state_root(root, "batch-2").await.unwrap();
        assert_eq!(r1.tx_ref, "inprocess:1");
        assert_eq!(r2.tx_ref, "inprocess:2", "无唯一索引：重复提交各自记账");
        assert_eq!(ledger.current_seq().await.unwrap(), 2, "各推一次链");

        // SQL 抽查：两行 kind/state_root、payload 各含 batch_ref
        let rows = sqlx::query(
            "SELECT payload::text AS payload FROM ledger_anchors \
             WHERE kind = 'state_root' ORDER BY id",
        )
        .fetch_all(&ledger.pool)
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        for (i, row) in rows.iter().enumerate() {
            let payload: String = row.get("payload");
            let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
            assert_eq!(
                v["batch_ref"],
                serde_json::json!(format!("batch-{}", i + 1))
            );
        }
    }

    /// 7 种 LedgerItem 各锚定一次全通过；kind/payload 抽查 2 种 SQL 断言。
    #[sqlx::test]
    async fn all_variants_anchor_once_with_kind_and_payload(pool: sqlx::PgPool) {
        let ledger = InProcessLedger::new(pool);
        for (i, item) in sample_items().into_iter().enumerate() {
            let receipt = ledger.anchor(item).await.unwrap();
            assert_eq!(receipt.tx_ref, format!("inprocess:{}", i + 1));
            assert!(receipt.in_process);
        }
        assert_eq!(ledger.current_seq().await.unwrap(), 7);

        // 抽查 1：nullifier 的 ref_hash = h 本身
        let h = Hash32::keccak(b"x");
        let row = sqlx::query("SELECT ref_hash FROM ledger_anchors WHERE kind = 'nullifier'")
            .fetch_one(&ledger.pool)
            .await
            .unwrap();
        let rh: Vec<u8> = row.get("ref_hash");
        assert_eq!(rh.as_slice(), h.as_bytes());

        // 抽查 2：encrypted_extra 的 payload 为相邻标签
        // {"type":"encrypted_extra","value":[1,2,3]}
        // （Vec<u8> serde 默认序列化为数字数组，非 hex）
        let row = sqlx::query(
            "SELECT payload::text AS payload FROM ledger_anchors \
             WHERE kind = 'encrypted_extra'",
        )
        .fetch_one(&ledger.pool)
        .await
        .unwrap();
        let payload: String = row.get("payload");
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["type"], serde_json::json!("encrypted_extra"));
        assert_eq!(v["value"], serde_json::json!([1, 2, 3]));
    }

    /// trait 对象使用（Box<dyn LedgerPort> 调用）+ Send+Sync 编译期哨兵。
    #[sqlx::test]
    async fn usable_as_trait_object(pool: sqlx::PgPool) {
        let ledger: Box<dyn LedgerPort> = Box::new(InProcessLedger::new(pool));
        let c = Hash32::keccak(b"obj-c");
        let receipt = ledger.anchor(LedgerItem::Commitment(c)).await.unwrap();
        assert_eq!(receipt.tx_ref, "inprocess:1");
        assert!(ledger.is_commitment_present(&c).await.unwrap());

        let root_receipt = ledger
            .submit_state_root(Hash32::keccak(b"obj-root"), "batch-obj")
            .await
            .unwrap();
        assert_eq!(root_receipt.tx_ref, "inprocess:2");
    }

    /// 编译期哨兵：实现与 trait 对象均满足 Send + Sync（服务端口约定）。
    #[test]
    fn inprocess_ledger_is_send_sync() {
        fn requires_send_sync<T: Send + Sync>() {}
        requires_send_sync::<InProcessLedger>();
        requires_send_sync::<Box<dyn LedgerPort>>();
    }

    /// anchored_at 时间在锚定时刻附近（合理窗口内，防时钟字段错位）。
    #[sqlx::test]
    async fn receipt_timestamp_is_recent(pool: sqlx::PgPool) {
        let ledger = InProcessLedger::new(pool);
        let before: DateTime<Utc> = Utc::now() - chrono::Duration::seconds(5);
        let receipt = ledger
            .anchor(LedgerItem::Nullifier(Hash32::keccak(b"ts")))
            .await
            .unwrap();
        assert!(receipt.anchored_at >= before);
        assert!(receipt.anchored_at <= Utc::now() + chrono::Duration::seconds(5));
    }
}
