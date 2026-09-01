//! 审计写入器：PostgreSQL 实现（只增）。
//!
//! **audit_events 表只增不更新不删除**（append-only，0001 迁移约定）：
//! [`PgAuditWriter`] 只提供 [`PgAuditWriter::append`] 一个写方法，无任何
//! UPDATE/DELETE 路径（编译即证），也无读方法（Task 22/24 查询侧按需再加）。

use chrono::{DateTime, Utc};

use vg_domain::shared::{Did, DomainError};

/// 审计条目（infra 侧定义；at 为业务时刻，落库列 `at`）。
///
/// **词表约定**（写入方 Task 19 / 查询方 Task 24 共同遵守）：
/// `action` 取 `IntentAction` 13 值的 snake_case 全集；`result` 仅取
/// `allow` / `deny` 二值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// 操作主体。
    pub actor: Did,
    /// 代理主体（Agent 代发时有值）。
    pub agent: Option<Did>,
    /// 关联意图 ID。
    pub intent_id: Option<String>,
    /// 动作名。
    pub action: String,
    /// 资源标识。
    pub resource: String,
    /// 命中的策略 ID（未命中为 None）。
    pub policy_id: Option<String>,
    /// 命中的策略版本（未命中为 None）。
    pub policy_version: Option<i64>,
    /// 关联证明 ID。
    pub proof_id: Option<String>,
    /// 结果（allow/deny 等结论）。
    pub result: String,
    /// 业务时刻。
    pub at: DateTime<Utc>,
}

/// 审计事件写入器（只增；Context 事务模式，与其余仓储同款）。
#[derive(Debug, Default, Clone, Copy)]
pub struct PgAuditWriter;

impl PgAuditWriter {
    /// 追加一条审计事件。
    ///
    /// 裸 INSERT（`id` 为 bigserial 自增）——审计表**只增**，无幂等去重、
    /// 无更新路径；同一动作重复审计产生多行是预期语义（审计流水而非状态）。
    pub async fn append(
        &self,
        ctx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        entry: &AuditEntry,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO audit_events \
                 (actor, agent, intent_id, action, resource, policy_id, policy_version, \
                  proof_id, result, at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(entry.actor.as_str())
        .bind(entry.agent.as_ref().map(Did::as_str))
        .bind(&entry.intent_id)
        .bind(&entry.action)
        .bind(&entry.resource)
        .bind(&entry.policy_id)
        .bind(entry.policy_version)
        .bind(&entry.proof_id)
        .bind(&entry.result)
        .bind(entry.at)
        .execute(&mut **ctx)
        .await
        .map_err(crate::storage)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use sqlx::Row;

    /// append 后直接 SQL 查行字段：全列断言（含 NULL 可空列）；无更新路径
    /// 由类型系统保证（本模块无 UPDATE 语句，编译即证）。
    #[sqlx::test]
    async fn append_writes_row_with_nullable_columns(pool: sqlx::PgPool) {
        let writer = PgAuditWriter;
        let mut tx = pool.begin().await.unwrap();

        let t = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let full = AuditEntry {
            actor: Did::parse("did:vg:user:reg-17").unwrap(),
            agent: Some(Did::parse("did:vg:agent:ag-17").unwrap()),
            intent_id: Some("it-17audit".into()),
            action: "transfer_product".into(),
            resource: "batch:bt-17".into(),
            policy_id: Some("pol-17a".into()),
            policy_version: Some(2),
            proof_id: Some("pf-17a".into()),
            result: "allow".into(),
            at: t,
        };
        writer.append(&mut tx, &full).await.expect("追加应成功");

        let row = sqlx::query(
            "SELECT actor, agent, intent_id, action, resource, policy_id, policy_version, \
                    proof_id, result, at \
             FROM audit_events WHERE intent_id = 'it-17audit'",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("审计行应存在");

        assert_eq!(row.get::<&str, _>("actor"), "did:vg:user:reg-17");
        assert_eq!(row.get::<Option<&str>, _>("agent"), Some("did:vg:agent:ag-17"));
        assert_eq!(row.get::<String, _>("action"), "transfer_product");
        assert_eq!(row.get::<String, _>("resource"), "batch:bt-17");
        assert_eq!(row.get::<Option<String>, _>("policy_id"), Some("pol-17a".into()));
        assert_eq!(row.get::<Option<i64>, _>("policy_version"), Some(2));
        assert_eq!(row.get::<Option<String>, _>("proof_id"), Some("pf-17a".into()));
        assert_eq!(row.get::<String, _>("result"), "allow");
        assert_eq!(row.get::<DateTime<Utc>, _>("at"), t);

        // 精简条目：可空列全 NULL 也应落库成功
        let minimal = AuditEntry {
            actor: Did::parse("did:vg:user:alice-17").unwrap(),
            agent: None,
            intent_id: None,
            action: "compliance_check".into(),
            resource: "asset:as-17".into(),
            policy_id: None,
            policy_version: None,
            proof_id: None,
            result: "deny".into(),
            at: t,
        };
        writer.append(&mut tx, &minimal).await.expect("精简条目应成功");
        let row = sqlx::query(
            "SELECT agent, intent_id, policy_id, policy_version, proof_id \
             FROM audit_events WHERE actor = 'did:vg:user:alice-17'",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("精简审计行应存在");
        assert_eq!(row.get::<Option<String>, _>("agent"), None);
        assert_eq!(row.get::<Option<String>, _>("intent_id"), None);
        assert_eq!(row.get::<Option<String>, _>("policy_id"), None);
        assert_eq!(row.get::<Option<i64>, _>("policy_version"), None);
        assert_eq!(row.get::<Option<String>, _>("proof_id"), None);

        tx.commit().await.unwrap();
    }
}
