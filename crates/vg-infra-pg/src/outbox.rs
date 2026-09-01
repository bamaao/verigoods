//! 领域事件 outbox：PostgreSQL 实现（append-only，Task 23 索引器消费）。
//!
//! [`PgOutbox`] 落 `domain_events` 表（bigserial 序 + dispatched 投递标记）：
//! 业务事务内 [`PgOutbox::append`]，投递器以 [`PgOutbox::pending`] 拉取、
//! 成功后 [`PgOutbox::mark_dispatched`]。**追加只增**，已投递行不删除
//! （dispatched 部分索引保证扫描只看待投递行）。

use chrono::{DateTime, Utc};

use vg_domain::events::DomainEvent;
use vg_domain::shared::DomainError;

/// outbox 待投递条目（infra 侧定义）。
#[derive(Debug, Clone, PartialEq)]
pub struct OutboxEntry {
    /// 表内自增序（投递位点与顺序依据）。
    pub serial: i64,
    /// 聚合标识（如 `batch:bt-17`，定位事件归属）。
    pub aggregate: String,
    /// 反序列化还原的领域事件。
    pub event: DomainEvent,
    /// 落库时刻。
    pub created_at: DateTime<Utc>,
}

/// 领域事件 outbox（Context 事务模式，与其余仓储同款）。
#[derive(Debug, Default, Clone, Copy)]
pub struct PgOutbox;

impl PgOutbox {
    /// 追加一条领域事件（append-only，裸 INSERT）。
    ///
    /// `event_type` 取自 [`DomainEvent`] serde 内部标签（`"event_type"` 字段，
    /// events.rs 锁定的规范形），`payload` 存整个序列化 JSON——读侧以
    /// `payload` 反序列化还原事件，`event_type` 仅供 SQL 层筛查/统计。
    pub async fn append(
        &self,
        ctx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        aggregate: &str,
        event: &DomainEvent,
    ) -> Result<(), DomainError> {
        let value = serde_json::to_value(event)
            .map_err(|e| DomainError::Storage(format!("领域事件序列化失败：{e}")))?;
        let event_type = value
            .get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                DomainError::Storage("领域事件序列化结果缺少 event_type 标签".into())
            })?;
        let payload = value.to_string();
        sqlx::query(
            "INSERT INTO domain_events (aggregate, event_type, payload) \
             VALUES ($1, $2, $3::jsonb)",
        )
        .bind(aggregate)
        .bind(event_type)
        .bind(payload)
        .execute(&mut **ctx)
        .await
        .map_err(crate::storage)?;
        Ok(())
    }

    /// 拉取最多 `limit` 条待投递条目，按 serial 升序（投递顺序即落库顺序）。
    pub async fn pending(
        &self,
        ctx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        limit: i64,
    ) -> Result<Vec<OutboxEntry>, DomainError> {
        let rows = sqlx::query(
            "SELECT id, aggregate, payload::text AS payload, created_at \
             FROM domain_events WHERE NOT dispatched ORDER BY id ASC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&mut **ctx)
        .await
        .map_err(crate::storage)?;

        use sqlx::Row;
        rows.iter()
            .map(|r| {
                let payload: String = r.get("payload");
                Ok(OutboxEntry {
                    serial: r.get("id"),
                    aggregate: r.get("aggregate"),
                    event: serde_json::from_str(&payload).map_err(|e| {
                        DomainError::Storage(format!("库中 domain_events.payload 非法：{e}"))
                    })?,
                    created_at: r.get("created_at"),
                })
            })
            .collect()
    }

    /// 标记条目已投递。
    ///
    /// **幂等静默**：serial 不存在或已标记时 0 行命中，同样返回 `Ok`
    /// （投递器重试语义——重复标记不是错误，无需区分首次与重放）。
    pub async fn mark_dispatched(
        &self,
        ctx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        serial: i64,
    ) -> Result<(), DomainError> {
        sqlx::query("UPDATE domain_events SET dispatched = true WHERE id = $1")
            .bind(serial)
            .execute(&mut **ctx)
            .await
            .map_err(crate::storage)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vg_domain::ownership::CustodyReason;
    use vg_domain::shared::{BatchId, Did, ProductId, SubjectRef};

    fn did(s: &str) -> Did {
        Did::parse(s).unwrap()
    }

    /// 追加 3 个不同 variant → pending 按 serial 序且 DomainEvent 深相等 →
    /// 全部标记投递后 pending 空；重复 mark_dispatched 幂等 Ok。
    #[sqlx::test]
    async fn append_pending_dispatch_roundtrip(pool: sqlx::PgPool) {
        let outbox = PgOutbox;
        let mut tx = pool.begin().await.unwrap();

        let events = vec![
            DomainEvent::BatchCreated {
                batch: BatchId::new("bt-17a"),
                product: ProductId::new("pt-17"),
                quantity: 100,
                producer: did("did:vg:user:alice-17"),
            },
            DomainEvent::CustodyChanged {
                subject: SubjectRef::Batch(BatchId::new("bt-17a")),
                from: None,
                to: did("did:vg:user:logi-17"),
                reason: CustodyReason::Ship,
            },
            DomainEvent::StateRootSubmitted {
                root: vg_domain::shared::Hash32::keccak(b"root-17"),
                batch_ref: "batch-17".into(),
            },
        ];
        for (i, event) in events.iter().enumerate() {
            let aggregate = if i == 2 { "validium" } else { "batch:bt-17a" };
            outbox
                .append(&mut tx, aggregate, event)
                .await
                .expect("追加应成功");
        }

        // pending：serial 升序、事件深相等还原、aggregate 随行
        let pending = outbox.pending(&mut tx, 10).await.expect("拉取应成功");
        assert_eq!(pending.len(), 3);
        assert!(
            pending[0].serial < pending[1].serial && pending[1].serial < pending[2].serial,
            "应按 serial 升序"
        );
        for (entry, event) in pending.iter().zip(&events) {
            assert_eq!(entry.event, *event, "DomainEvent 应深相等还原");
        }
        assert_eq!(pending[0].aggregate, "batch:bt-17a");
        assert_eq!(pending[2].aggregate, "validium");

        // LIMIT 生效
        assert_eq!(
            outbox.pending(&mut tx, 2).await.unwrap().len(),
            2,
            "LIMIT 应截断"
        );

        // 逐条投递
        for entry in &pending {
            outbox
                .mark_dispatched(&mut tx, entry.serial)
                .await
                .expect("标记应成功");
        }
        assert!(
            outbox.pending(&mut tx, 10).await.unwrap().is_empty(),
            "全部投递后 pending 应为空"
        );

        // 重复标记幂等 Ok（0 行命中静默）
        outbox
            .mark_dispatched(&mut tx, pending[0].serial)
            .await
            .expect("重复标记应幂等 Ok");
        // 不存在的 serial 同样静默
        outbox
            .mark_dispatched(&mut tx, 987654321)
            .await
            .expect("未知 serial 应静默 Ok");

        tx.commit().await.unwrap();
    }
}
