//! vg-infra-pg：PostgreSQL 基础设施层。
//!
//! 本 crate 承载 sqlx 迁移（`migrations/0001_init.sql`，全量表）与连接池
//! 构造；仓储实现自 Task 15 起填充。迁移经 [`migrate`] 应用，Task 23 的
//! bootstrap 将复用 [`pool::connect`] + [`migrate`] 组合完成库初始化。

pub mod pool;

/// 应用内嵌迁移到目标库。
///
/// sqlx 自带 `_sqlx_migrations` 版本表：已应用的迁移自动跳过，
/// 因此重复调用是安全的 no-op（幂等）。
pub async fn migrate(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    /// 环境固定：本机 PostgreSQL 17，trust 认证无密码。
    const DATABASE_URL: &str = "postgres://postgres@localhost:5432/verigoods";

    /// 期望的全量表集合（不含 sqlx 自身的 `_sqlx_migrations`）。
    const EXPECTED_TABLES: &[&str] = &[
        "assets",
        "audit_events",
        "batch_lineage",
        "batches",
        "capabilities",
        "credentials",
        "custody_states",
        "data_access_grants",
        "dids",
        "domain_events",
        "intents",
        "ledger_anchors",
        "notes",
        "nullifiers",
        "ownership_states",
        "policies",
        "products",
        "proofs",
        "regulatory_domains",
        "shielded_txs",
        "transfers",
        "validium_batches",
        "verification_methods",
    ];

    /// 迁移可应用且幂等：表集合与期望完全一致，关键约束存在。
    #[tokio::test]
    async fn migrations_apply() {
        let pool = pool::connect(DATABASE_URL).await.expect("连接应成功");

        // 首次（或库为空时）应用
        migrate(&pool).await.expect("迁移应成功");
        // 二次应用为 no-op（sqlx 版本表去重），验证幂等可重跑
        migrate(&pool).await.expect("重复迁移应为 no-op");

        // 断言表集合与期望完全一致（无遗漏、无多余业务表）
        let rows = sqlx::query(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_name <> '_sqlx_migrations' \
             ORDER BY table_name",
        )
        .fetch_all(&pool)
        .await
        .expect("查询表清单应成功");
        let actual: Vec<String> = rows
            .iter()
            .map(|r| r.get::<String, _>("table_name"))
            .collect();
        let expected: Vec<String> = EXPECTED_TABLES.iter().map(|s| s.to_string()).collect();
        assert_eq!(actual, expected, "表集合应与期望完全一致");

        // 抽查：ledger_anchors 幂等部分唯一索引存在
        let idx = sqlx::query(
            "SELECT indexdef FROM pg_indexes \
             WHERE schemaname = 'public' AND indexname = 'uq_ledger_anchors_idempotent'",
        )
        .fetch_optional(&pool)
        .await
        .expect("查询索引应成功")
        .expect("ledger_anchors 幂等索引应存在");
        let def: String = idx.get("indexdef");
        assert!(
            def.contains("UNIQUE") && def.contains("WHERE"),
            "幂等索引应为带 WHERE 的唯一索引：{def}"
        );

        // 抽查：CHECK 白名单生效（非法 lifecycle 状态应被拒绝）
        let bad_state = sqlx::query(
            "INSERT INTO batches (id, product_id, quantity, unit, produced_at, producer, state) \
             VALUES ('t-bad', 't-p', 1, 'kg', now(), 't-did', 'teleported')",
        )
        .execute(&pool)
        .await;
        assert!(bad_state.is_err(), "非法 lifecycle 状态应违反 CHECK");
    }
}
