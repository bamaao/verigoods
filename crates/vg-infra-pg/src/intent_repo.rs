//! 意图仓储：PostgreSQL 实现（Context 事务模式，与 identity/commodity 同款）。
//!
//! [`PgIntentRepository`] 实现 [`IntentRepository`]：`intents` 表的幂等两层
//! （PK(id) + UNIQUE(actor, nonce)，0001 迁移）由 `ON CONFLICT DO NOTHING` +
//! 行计数承载，避免唯一约束违例中止整个事务（与 ownership_repo 同一教训）。

use async_trait::async_trait;
use sqlx::Row;

use vg_domain::intent::ports::IntentRepository;
use vg_domain::intent::{Intent, IntentAction, IntentStatus, RiskLevel};
use vg_domain::shared::{Did, DomainError, IntentId};

use crate::{enum_from_text, enum_to_text, parse_did, storage, uint_from_db};

/// intent 上下文的 PostgreSQL 仓储。
#[derive(Debug, Default, Clone, Copy)]
pub struct PgIntentRepository;

/// 枚举文本还原的损坏数据包装（字段名编入错误消息）。
fn enum_corrupt<T: serde::de::DeserializeOwned>(
    field: &str,
    text: &str,
) -> Result<T, DomainError> {
    enum_from_text(text)
        .map_err(|e| DomainError::Storage(format!("库中 intents.{field} `{text}` 非法：{e}")))
}

/// 行 → Intent 还原；任何列损坏（非法 DID/枚举/超界整数）报 Storage 错误。
fn row_to_intent(row: &sqlx::postgres::PgRow) -> Result<Intent, DomainError> {
    let action: String = row.get("action");
    let status: String = row.get("status");
    let risk: String = row.get("risk");
    let actor: String = row.get("actor");
    let on_behalf_of: Option<String> = row.get("on_behalf_of");
    let payload: String = row.get("payload");
    Ok(Intent {
        id: IntentId::new(row.get::<String, _>("id")),
        action: enum_corrupt::<IntentAction>("action", &action)?,
        actor: parse_did(&actor)?,
        on_behalf_of: on_behalf_of
            .as_deref()
            .map(parse_did)
            .transpose()?,
        payload: serde_json::from_str(&payload)
            .map_err(|e| DomainError::Storage(format!("库中 intents.payload 非法：{e}")))?,
        nonce: uint_from_db(row.get("nonce"), "intent nonce")?,
        created_at: row.get("created_at"),
        expires_at: row.get("expires_at"),
        status: enum_corrupt::<IntentStatus>("status", &status)?,
        rejection: row.get("rejection"),
        risk: enum_corrupt::<RiskLevel>("risk", &risk)?,
        result_ref: row.get("result_ref"),
    })
}

#[async_trait]
impl IntentRepository for PgIntentRepository {
    type Context = sqlx::Transaction<'static, sqlx::Postgres>;

    /// 插入新 Intent；冲突返回 [`DomainError::AlreadyExists`]（幂等信号，
    /// 上层可返回既有结果）。
    ///
    /// `ON CONFLICT DO NOTHING` 不带冲突目标，同时覆盖 id PK 与
    /// (actor, nonce) UNIQUE 两层幂等，且不会中止外层事务（唯一约束
    /// 违例会中止整个 PostgreSQL 事务，见 lib.rs `is_unique_violation` 注）。
    ///
    /// 返回 0 行的两种成因由调用方经 [`IntentRepository::get`] 区分：
    /// `Some` = 同意图 id 重放（幂等同意图），`None` = (actor, nonce)
    /// 冲突的异意图（防重放拒绝）。
    async fn insert(
        &self,
        ctx: &mut Self::Context,
        intent: &Intent,
    ) -> Result<(), DomainError> {
        let payload_text = serde_json::to_string(&intent.payload)
            .map_err(|e| DomainError::Storage(format!("payload 序列化失败：{e}")))?;
        let result = sqlx::query(
            "INSERT INTO intents \
                 (id, action, actor, on_behalf_of, payload, nonce, status, risk, \
                  rejection, result_ref, created_at, expires_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12, now()) \
             ON CONFLICT DO NOTHING",
        )
        .bind(intent.id.as_ref())
        .bind(enum_to_text(&intent.action))
        .bind(intent.actor.as_str())
        .bind(intent.on_behalf_of.as_ref().map(Did::as_str))
        .bind(payload_text)
        .bind(intent.nonce as i64)
        .bind(enum_to_text(&intent.status))
        .bind(enum_to_text(&intent.risk))
        .bind(&intent.rejection)
        .bind(&intent.result_ref)
        .bind(intent.created_at)
        .bind(intent.expires_at)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        if result.rows_affected() == 0 {
            return Err(DomainError::AlreadyExists);
        }
        Ok(())
    }

    /// 按 ID 查找；不存在时返回 `Ok(None)`。全字段还原（枚举/可空列/jsonb）。
    async fn get(
        &self,
        ctx: &mut Self::Context,
        id: &IntentId,
    ) -> Result<Option<Intent>, DomainError> {
        let row = sqlx::query(
            "SELECT id, action, actor, on_behalf_of, payload::text AS payload, nonce, \
                    status, risk, rejection, result_ref, created_at, expires_at \
             FROM intents WHERE id = $1",
        )
        .bind(id.as_ref())
        .fetch_optional(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(row.map(|r| row_to_intent(&r)).transpose()?)
    }

    /// 全量持久化 Intent（含 rejection/result_ref 等侧字段），upsert 语义：
    /// id 已存在时更新全部可变字段（status/risk/payload/nonce/expires_at/
    /// rejection/result_ref），`created_at` 保留首建值、`updated_at = now()`。
    ///
    /// 供 reject(reason)/confirm(result_ref) 后的落库路径。
    async fn save(
        &self,
        ctx: &mut Self::Context,
        intent: &Intent,
    ) -> Result<(), DomainError> {
        let payload_text = serde_json::to_string(&intent.payload)
            .map_err(|e| DomainError::Storage(format!("payload 序列化失败：{e}")))?;
        sqlx::query(
            "INSERT INTO intents \
                 (id, action, actor, on_behalf_of, payload, nonce, status, risk, \
                  rejection, result_ref, created_at, expires_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11, $12, now()) \
             ON CONFLICT (id) DO UPDATE SET \
                 action = EXCLUDED.action, \
                 actor = EXCLUDED.actor, \
                 on_behalf_of = EXCLUDED.on_behalf_of, \
                 payload = EXCLUDED.payload, \
                 nonce = EXCLUDED.nonce, \
                 status = EXCLUDED.status, \
                 risk = EXCLUDED.risk, \
                 rejection = EXCLUDED.rejection, \
                 result_ref = EXCLUDED.result_ref, \
                 expires_at = EXCLUDED.expires_at, \
                 updated_at = now()",
        )
        .bind(intent.id.as_ref())
        .bind(enum_to_text(&intent.action))
        .bind(intent.actor.as_str())
        .bind(intent.on_behalf_of.as_ref().map(Did::as_str))
        .bind(payload_text)
        .bind(intent.nonce as i64)
        .bind(enum_to_text(&intent.status))
        .bind(enum_to_text(&intent.risk))
        .bind(&intent.rejection)
        .bind(&intent.result_ref)
        .bind(intent.created_at)
        .bind(intent.expires_at)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// 薄写入：仅持久化 status（领域端口契约；rejection/result_ref 走 save）。
    ///
    /// 0 行命中（id 不存在）→ [`DomainError::NotFound`]。
    async fn update_status(
        &self,
        ctx: &mut Self::Context,
        id: &IntentId,
        to: &IntentStatus,
    ) -> Result<(), DomainError> {
        let result =
            sqlx::query("UPDATE intents SET status = $2, updated_at = now() WHERE id = $1")
                .bind(id.as_ref())
                .bind(enum_to_text(to))
                .execute(&mut **ctx)
                .await
                .map_err(storage)?;
        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound);
        }
        Ok(())
    }

    /// 列出全部非终态 Intent（供管道调度轮询推进）。
    ///
    /// **含已过期但未推进的项**：仓储不做时间假设，调用方须自行用
    /// [`Intent::is_replay_safe`] 过滤（领域端口契约）。
    /// `ORDER BY created_at, id` 保证推进顺序确定（同 created_at 以 id 决胜）。
    ///
    /// **量级假设**：Phase1 无分页，假设非终态为管道工作集（少数）；
    /// 若终态堆积致大表，需补 LIMIT + 游标分页。
    async fn list_pending(&self, ctx: &mut Self::Context) -> Result<Vec<Intent>, DomainError> {
        let rows = sqlx::query(
            "SELECT id, action, actor, on_behalf_of, payload::text AS payload, nonce, \
                    status, risk, rejection, result_ref, created_at, expires_at \
             FROM intents \
             WHERE status NOT IN ('confirmed','rejected','expired','cancelled') \
             ORDER BY created_at ASC, id ASC",
        )
        .fetch_all(&mut **ctx)
        .await
        .map_err(storage)?;
        rows.iter().map(row_to_intent).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use serde_json::json;

    fn t(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, hour, 0, 0).unwrap()
    }

    fn sample_intent(id: &str, nonce: u64, created_hour: u32) -> Intent {
        Intent::new(
            IntentId::new(id),
            IntentAction::TransferProduct,
            Did::parse("did:vg:user:alice-17").unwrap(),
            Some(Did::parse("did:vg:org:acme-17").unwrap()),
            json!({"qty": 10, "to": {"did": "did:vg:user:bob", "region": "CN"}}),
            nonce,
            t(created_hour),
            t(created_hour) + chrono::Duration::hours(24),
        )
        .expect("样本构造应成功")
    }

    /// insert → get 深相等：L3 风险（TransferProduct 推导）、on_behalf_of Some、
    /// 嵌套 json payload、无终态侧字段。
    #[sqlx::test]
    async fn insert_get_roundtrip(pool: sqlx::PgPool) {
        let repo = PgIntentRepository;
        let mut tx = pool.begin().await.unwrap();

        let intent = sample_intent("it-17a", 1, 0);
        repo.insert(&mut tx, &intent).await.expect("插入应成功");
        let got = repo
            .get(&mut tx, &IntentId::new("it-17a"))
            .await
            .expect("查询应成功")
            .expect("刚插入的应能查到");
        assert_eq!(got, intent, "全字段深相等往返");
        assert_eq!(got.risk, RiskLevel::L3);
        assert!(got.on_behalf_of.is_some());

        assert!(repo
            .get(&mut tx, &IntentId::new("it-none"))
            .await
            .expect("查询应成功")
            .is_none());

        tx.commit().await.unwrap();
    }

    /// 重复 id → AlreadyExists 且**事务不中止**（后续继续 get 到原值）；
    /// 同 (actor, nonce) 异 id → 同样 AlreadyExists，且经 get 可区分成因
    /// （Some=同意图幂等 / None=nonce 冲突）。
    #[sqlx::test]
    async fn insert_conflicts_are_already_exists_without_aborting(pool: sqlx::PgPool) {
        let repo = PgIntentRepository;
        let mut tx = pool.begin().await.unwrap();

        let first = sample_intent("it-17b", 7, 0);
        repo.insert(&mut tx, &first).await.expect("首次插入应成功");

        // 同 id 重放：AlreadyExists
        let dup = sample_intent("it-17b", 99, 1);
        match repo.insert(&mut tx, &dup).await {
            Err(DomainError::AlreadyExists) => {}
            other => panic!("同 id 重放应报 AlreadyExists，实际：{other:?}"),
        }
        // 事务未中止：同一事务继续查询仍得到原值（nonce 未被覆盖）
        let got = repo
            .get(&mut tx, &IntentId::new("it-17b"))
            .await
            .expect("冲突后查询应仍成功（事务未中止）")
            .expect("原记录应存在");
        assert_eq!(got.nonce, 7, "冲突插入不得覆盖原记录");

        // 同 (actor, nonce) 异 id：同样 AlreadyExists，且 get(id)=None 可区分成因
        let nonce_clash = sample_intent("it-17c", 7, 2);
        match repo.insert(&mut tx, &nonce_clash).await {
            Err(DomainError::AlreadyExists) => {}
            other => panic!("(actor,nonce) 冲突应报 AlreadyExists，实际：{other:?}"),
        }
        assert!(
            repo.get(&mut tx, &IntentId::new("it-17c"))
                .await
                .expect("查询应成功")
                .is_none(),
            "nonce 冲突方未落库——get 为 None 即区分于同意图幂等"
        );

        tx.commit().await.unwrap();
    }

    /// save 更新 rejection/result_ref 后 get 还原（reject 场景），
    /// 且 created_at 保留首建值。
    #[sqlx::test]
    async fn save_persists_side_fields_and_keeps_created_at(pool: sqlx::PgPool) {
        let repo = PgIntentRepository;
        let mut tx = pool.begin().await.unwrap();

        let original = sample_intent("it-17d", 3, 0);
        repo.insert(&mut tx, &original).await.expect("插入应成功");

        // reject 后 save：rejection 落库
        let mut rejected = original.clone();
        rejected.reject("凭证缺失").expect("reject 应成功");
        repo.save(&mut tx, &rejected).await.expect("save 应成功");
        let got = repo
            .get(&mut tx, &IntentId::new("it-17d"))
            .await
            .unwrap()
            .expect("应存在");
        assert_eq!(got.status, IntentStatus::Rejected);
        assert_eq!(got.rejection.as_deref(), Some("凭证缺失"));
        assert_eq!(got.created_at, original.created_at, "created_at 保留首建值");

        // confirm 场景：从 Submitted 一路推进后 confirm + save → result_ref 落库
        let mut flow = sample_intent("it-17e", 4, 0);
        repo.insert(&mut tx, &flow).await.expect("flow 首插应成功");
        for to in [
            IntentStatus::Validated,
            IntentStatus::Authorized,
            IntentStatus::PolicyChecked,
            IntentStatus::ProofRequired,
            IntentStatus::Proved,
            IntentStatus::Approved,
            IntentStatus::Submitted,
        ] {
            flow.advance(to).expect("推进应成功");
            repo.update_status(&mut tx, &flow.id, &to)
                .await
                .expect("update_status 应成功");
        }
        flow.confirm("0xdeadbeef").expect("confirm 应成功");
        repo.save(&mut tx, &flow).await.expect("save 应成功");
        let got = repo
            .get(&mut tx, &IntentId::new("it-17e"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.status, IntentStatus::Confirmed);
        assert_eq!(got.result_ref.as_deref(), Some("0xdeadbeef"));

        // update_status 对不存在 id → NotFound
        match repo
            .update_status(&mut tx, &IntentId::new("it-none"), &IntentStatus::Validated)
            .await
        {
            Err(DomainError::NotFound) => {}
            other => panic!("更新不存在的 id 应报 NotFound，实际：{other:?}"),
        }

        tx.commit().await.unwrap();
    }

    /// list_pending：只含非终态、含已过期未推进项、按 created_at 升序。
    #[sqlx::test]
    async fn list_pending_excludes_terminal_keeps_expired_ordered(pool: sqlx::PgPool) {
        let repo = PgIntentRepository;
        let mut tx = pool.begin().await.unwrap();

        // 乱序插入：小时 2、0、1
        let later = sample_intent("it-17p3", 30, 2);
        let early = sample_intent("it-17p1", 10, 0);
        let mid = sample_intent("it-17p2", 20, 1);
        repo.insert(&mut tx, &later).await.unwrap();
        repo.insert(&mut tx, &early).await.unwrap();
        repo.insert(&mut tx, &mid).await.unwrap();

        // 终态项：rejected（带 rejection）与 confirmed（带 result_ref）
        let mut rejected = sample_intent("it-17rj", 40, 0);
        rejected.reject("驳回").unwrap();
        repo.insert(&mut tx, &rejected).await.unwrap();

        // 已过期未推进：created 在 t-48h、expires 在 t-24h（早已过期，仍 Created）
        let mut stale = sample_intent("it-17st", 50, 0);
        stale.created_at = t(0) - chrono::Duration::hours(48);
        stale.expires_at = t(0) - chrono::Duration::hours(24);
        repo.insert(&mut tx, &stale).await.unwrap();

        let pending = repo.list_pending(&mut tx).await.expect("查询应成功");
        let ids: Vec<String> = pending.iter().map(|i| i.id.to_string()).collect();
        assert_eq!(
            ids,
            vec![
                "it-17st".to_string(),
                "it-17p1".to_string(),
                "it-17p2".to_string(),
                "it-17p3".to_string(),
            ],
            "created_at 升序（it-17st 建于 48h 前故最前，含已过期未推进项），终态 it-17rj 排除"
        );
        assert!(pending.iter().all(|i| !i.status.is_terminal()));
        assert!(!pending
            .iter()
            .any(|i| i.id == IntentId::new("it-17rj")));

        tx.commit().await.unwrap();
    }
}
