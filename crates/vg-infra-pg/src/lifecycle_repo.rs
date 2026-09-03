//! 生命周期仓储：PostgreSQL 实现（Context 事务模式，与 identity 同款）。
//!
//! [`PgLifecycleRepo`] 实现 [`LifecycleRepository`]，落 `lifecycle_events`
//! 追加式事件日志（0003）。append 以 `id` 为主键幂等；history /
//! current_state 以 `(subject, at)` 索引扫描，`at` 同刻时以 `id` 破平局
//! 保证稳定序。

use async_trait::async_trait;
use sqlx::Row;

use vg_domain::lifecycle::ports::LifecycleRepository;
use vg_domain::lifecycle::{LifecycleEvent, LifecycleState};
use vg_domain::shared::{DomainError, IntentId, ProofId, SubjectRef};

use crate::{decode_subject, encode_subject, enum_from_text, enum_to_text, storage, uint_from_db};

/// 生命周期事件的 PostgreSQL 仓储。
#[derive(Debug, Default, Clone, Copy)]
pub struct PgLifecycleRepo;

/// 库中文本 → [`LifecycleState`] 的损坏数据包装。
fn map_state(text: &str) -> Result<LifecycleState, DomainError> {
    enum_from_text(text)
        .map_err(|e| DomainError::Storage(format!("库中生命周期状态 `{text}` 非法：{e}")))
}

#[async_trait]
impl LifecycleRepository for PgLifecycleRepo {
    type Context = sqlx::Transaction<'static, sqlx::Postgres>;

    /// 追加一条事件：`ON CONFLICT (id) DO NOTHING` 承载按 `event.id`
    /// 的幂等（同一事件重复追加不报错、不产生新条目）。
    async fn append(
        &self,
        ctx: &mut Self::Context,
        event: &LifecycleEvent,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO lifecycle_events \
                 (id, subject, from_state, to_state, reason, intent_id, \
                  proof_id, policy_version, at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&event.id)
        .bind(encode_subject(&event.subject))
        .bind(enum_to_text(&event.from))
        .bind(enum_to_text(&event.to))
        .bind(&event.reason)
        .bind(event.intent_id.as_ref())
        .bind(event.proof_id.as_ref().map(ProofId::as_ref))
        .bind(event.policy_version.map(|v| v as i64))
        .bind(event.at)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// 按主体回放事件：`ORDER BY at ASC, id ASC`（追加序；同一 `at` 刻以
    /// `id` 破平局，保证结果确定）。
    async fn history(
        &self,
        ctx: &mut Self::Context,
        subject: &SubjectRef,
    ) -> Result<Vec<LifecycleEvent>, DomainError> {
        let rows = sqlx::query(
            "SELECT id, subject, from_state, to_state, reason, intent_id, \
                    proof_id, policy_version, at \
             FROM lifecycle_events WHERE subject = $1 ORDER BY at ASC, id ASC",
        )
        .bind(encode_subject(subject))
        .fetch_all(&mut **ctx)
        .await
        .map_err(storage)?;
        rows.iter().map(map_event).collect()
    }

    /// 当前状态：最后一条事件的 `to`；无事件 → `None`。
    ///
    /// `ORDER BY at DESC, id DESC LIMIT 1` 只取末条（与 history 同一排序
    /// 口径的倒序取首），避免全量拉取。
    async fn current_state(
        &self,
        ctx: &mut Self::Context,
        subject: &SubjectRef,
    ) -> Result<Option<LifecycleState>, DomainError> {
        let row = sqlx::query(
            "SELECT to_state FROM lifecycle_events WHERE subject = $1 \
             ORDER BY at DESC, id DESC LIMIT 1",
        )
        .bind(encode_subject(subject))
        .fetch_optional(&mut **ctx)
        .await
        .map_err(storage)?;
        row.map(|r| map_state(r.get("to_state"))).transpose()
    }
}

/// 行 → [`LifecycleEvent`]。
fn map_event(r: &sqlx::postgres::PgRow) -> Result<LifecycleEvent, DomainError> {
    let from_state: String = r.get("from_state");
    let to_state: String = r.get("to_state");
    let intent_id: String = r.get("intent_id");
    let proof_id: Option<String> = r.get("proof_id");
    let policy_version: Option<i64> = r.get("policy_version");
    Ok(LifecycleEvent {
        id: r.get("id"),
        subject: decode_subject(r.get("subject"))?,
        from: map_state(&from_state)?,
        to: map_state(&to_state)?,
        reason: r.get("reason"),
        intent_id: IntentId::new(intent_id),
        proof_id: proof_id.map(ProofId::new),
        policy_version: policy_version
            .map(|v| uint_from_db(v, "policy_version"))
            .transpose()?,
        at: r.get("at"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use vg_domain::shared::{AssetId, BatchId};

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 0, 0, 0).unwrap()
    }

    fn later_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 6, 0, 0).unwrap()
    }

    fn make_event(
        id: &str,
        subject: &SubjectRef,
        from: LifecycleState,
        to: LifecycleState,
    ) -> LifecycleEvent {
        LifecycleEvent::new(
            id,
            subject.clone(),
            from,
            to,
            Some("产线下线".into()),
            IntentId::new("it-16"),
            Some(ProofId::new("pf-16")),
            Some(1),
            fixed_time(),
        )
        .expect("合法迁移的事件构造应成功")
    }

    /// append → history 按序 → current_state 取末条 to；无事件 None；
    /// 同 id 二次 append 幂等；batch/asset 双主体隔离。
    #[sqlx::test]
    async fn append_history_current_state_and_idempotency(pool: sqlx::PgPool) {
        let repo = PgLifecycleRepo;
        let mut tx = pool.begin().await.unwrap();

        let subject = SubjectRef::Batch(BatchId::new("b-lc"));
        // 空历史：current_state None、history 空
        assert_eq!(repo.current_state(&mut tx, &subject).await.unwrap(), None);
        assert!(repo.history(&mut tx, &subject).await.unwrap().is_empty());

        // 两段迁移依次追加
        let e1 = make_event(
            "evt-lc-1",
            &subject,
            LifecycleState::Created,
            LifecycleState::Produced,
        );
        let e2 = make_event(
            "evt-lc-2",
            &subject,
            LifecycleState::Produced,
            LifecycleState::InWarehouse,
        );
        // e2 用更晚时刻（later_time 也要带：make_event 固定 fixed_time，
        // 故这里手工调 at 保证 at 有序）
        let e2 = LifecycleEvent {
            at: later_time(),
            ..e2
        };
        repo.append(&mut tx, &e1).await.expect("追加 e1 应成功");
        repo.append(&mut tx, &e2).await.expect("追加 e2 应成功");

        let history = repo.history(&mut tx, &subject).await.unwrap();
        assert_eq!(history, vec![e1.clone(), e2.clone()], "按 at 升序回放");

        // current_state = 末条 to
        assert_eq!(
            repo.current_state(&mut tx, &subject).await.unwrap(),
            Some(LifecycleState::InWarehouse)
        );

        // 幂等：同 id 二次 append Ok 且不新增
        repo.append(&mut tx, &e1).await.expect("重复追加应幂等成功");
        assert_eq!(repo.history(&mut tx, &subject).await.unwrap().len(), 2);

        // asset 主体：独立建档 + 与 batch 主体互不可见
        let asset_subject = SubjectRef::Asset(AssetId::new("a-lc"));
        let e3 = make_event(
            "evt-lc-3",
            &asset_subject,
            LifecycleState::Created,
            LifecycleState::Produced,
        );
        repo.append(&mut tx, &e3).await.unwrap();
        assert_eq!(
            repo.history(&mut tx, &asset_subject).await.unwrap(),
            vec![e3.clone()],
            "asset 主体应只见自己的事件"
        );
        assert_eq!(
            repo.current_state(&mut tx, &asset_subject).await.unwrap(),
            Some(LifecycleState::Produced)
        );
        assert_eq!(repo.history(&mut tx, &subject).await.unwrap().len(), 2);

        tx.commit().await.unwrap();
    }

    /// 可选字段（reason/proof_id/policy_version 为 None）无损往返；
    /// 同刻两条事件按 id 破平局稳定排序。
    #[sqlx::test]
    async fn optional_fields_roundtrip_and_same_at_tiebreak(pool: sqlx::PgPool) {
        let repo = PgLifecycleRepo;
        let mut tx = pool.begin().await.unwrap();

        let subject = SubjectRef::Batch(BatchId::new("b-lc-opt"));
        let base = LifecycleEvent::new(
            "evt-opt-b",
            subject.clone(),
            LifecycleState::Created,
            LifecycleState::Produced,
            None,
            IntentId::new("it-opt"),
            None,
            None,
            fixed_time(),
        )
        .unwrap();
        let tie_a = LifecycleEvent {
            id: "evt-opt-a".into(),
            ..base.clone()
        };
        // 与 tie_a 同一 from→to 同一时刻：仅 id 不同（id 序即稳定序）
        repo.append(&mut tx, &tie_a).await.unwrap();
        repo.append(&mut tx, &base).await.unwrap();

        let history = repo.history(&mut tx, &subject).await.unwrap();
        assert_eq!(
            (history[0].id.as_ref(), history[1].id.as_ref()),
            ("evt-opt-a", "evt-opt-b"),
            "同刻事件应按 id 升序破平局"
        );
        // 可选字段 None 无损还原
        assert_eq!(history[1].reason, None);
        assert_eq!(history[1].proof_id, None);
        assert_eq!(history[1].policy_version, None);

        // 同 id 幂等：改写 payload 的同 id 追加被忽略（先落者胜出）
        let mutated = LifecycleEvent {
            reason: Some("篡改".into()),
            ..tie_a
        };
        repo.append(&mut tx, &mutated).await.unwrap();
        assert_eq!(
            repo.history(&mut tx, &subject).await.unwrap()[0].reason,
            None,
            "同 id 二次 append 不得改写已落库事件"
        );

        tx.commit().await.unwrap();
    }
}
