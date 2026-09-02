//! vg-infra-pg：PostgreSQL 基础设施层。
//!
//! 本 crate 承载 sqlx 迁移（`migrations/`，0001 全量表 + 0002 jurisdiction
//! 可空化 + 0003 生命周期事件表 + 0004 转移记录列/谱系时间列）、
//! 连接池构造与领域仓储实现（Context 事务模式：`Context` 绑定
//! `sqlx::Transaction<'static, Postgres>`，由 application 层编排提交/回滚）。
//! 迁移经 [`migrate`] 应用，Task 23 的 bootstrap 将复用 [`pool::connect`] +
//! [`migrate`] 组合完成库初始化。
//!
//! 已实现仓储：
//! - [`identity_repo`]：DID 文档 / 能力委托（Task 15）；
//! - [`credential_repo`]：可验证凭证（Task 15）；
//! - [`commodity_repo`]：商品类型 / 批次 / 单品 / 谱系（Task 16）；
//! - [`ownership_repo`]：所有权 / 保管 / 转移流水（Task 16）；
//! - [`lifecycle_repo`]：生命周期事件日志（Task 16）；
//! - [`policy_repo`]：监管域 / 策略版本（Task 17）；
//! - [`intent_repo`]：意图管道（Task 17）；
//! - [`proof_store`]：ZK 证明存档（Task 17，Task 19/20 使用）；
//! - [`audit`]：审计事件写入，只增（Task 17）；
//! - [`outbox`]：领域事件 outbox（Task 17，Task 23 索引器消费）。

pub mod approvals;
pub mod audit;
pub mod commodity_repo;
pub mod credential_repo;
pub mod identity_repo;
pub mod intent_repo;
pub mod ledger_inprocess;
pub mod lifecycle_repo;
pub mod outbox;
pub mod ownership_repo;
pub mod policy_repo;
pub mod pool;
pub mod proof_store;

pub use approvals::{ApprovalRow, PgApprovalsStore};
pub use audit::{AuditEntry, PgAuditWriter};
pub use commodity_repo::PgCommodityRepo;
pub use credential_repo::PgCredentialRepo;
pub use identity_repo::PgIdentityRepo;
pub use intent_repo::PgIntentRepository;
pub use ledger_inprocess::InProcessLedger;
pub use lifecycle_repo::PgLifecycleRepo;
pub use outbox::{OutboxEntry, PgOutbox};
pub use ownership_repo::PgOwnershipRepo;
pub use policy_repo::PgPolicyRepository;
pub use proof_store::{PgProofStore, ProofRecord};

/// sqlx 错误 → 领域存储错误的统一映射。
///
/// 保留错误结构：数据库层错误在消息尾部编入 SQLSTATE（如 `[23505]`），
/// 供日志排查与调用方按码分诊，避免 `to_string` 压平后信息丢失。
pub(crate) fn storage(e: sqlx::Error) -> vg_domain::shared::DomainError {
    // code() 返回 Option<Cow<str>>：数据库错误必有 SQLSTATE，非 DB 错误
    // （连接/解码等）无码，附加段留空
    let detail = e
        .as_database_error()
        .and_then(|d| d.code().map(|c| format!(" [{c}]")))
        .unwrap_or_default();
    vg_domain::shared::DomainError::Storage(format!("{e}{detail}"))
}

/// 从库中文本还原 DID；解析失败说明存储层数据损坏，报 Storage 错误。
///
/// identity / credential 两仓储共用（Task 16/17 仓储沿用本工具集）。
pub(crate) fn parse_did(
    raw: &str,
) -> Result<vg_domain::shared::Did, vg_domain::shared::DomainError> {
    vg_domain::shared::Did::parse(raw)
        .map_err(|e| vg_domain::shared::DomainError::Storage(format!("库中 DID `{raw}` 非法：{e}")))
}

/// bigint → u32/u64 等无符号整数还原；负数/超界说明存储层数据损坏，
/// 报 Storage 错误（与 [`parse_did`] 同口径）。三仓储共用。
pub(crate) fn uint_from_db<T: TryFrom<i64>>(
    raw: i64,
    field: &str,
) -> Result<T, vg_domain::shared::DomainError> {
    T::try_from(raw).map_err(|_| {
        vg_domain::shared::DomainError::Storage(format!("库中 {field} `{raw}` 超出无符号整数口径"))
    })
}

/// 领域枚举（serde snake_case）→ 库中文本。
///
/// 经 serde 序列化取字符串而非手写 match，保证与领域枚举的
/// serde 命名（也是 CHECK 白名单口径）永不漂移。
pub(crate) fn enum_to_text<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        // 领域枚举均为 unit variant，序列化必为字符串；到达即编程错误
        Ok(other) => unreachable!("领域枚举序列化应为字符串，实际 {other}"),
        Err(e) => unreachable!("领域枚举序列化不应失败：{e}"),
    }
}

/// 库中文本 → 领域枚举；未知值报 serde 数据错误（由调用方包装为 Storage）。
pub(crate) fn enum_from_text<T: serde::de::DeserializeOwned>(
    text: &str,
) -> Result<T, serde_json::Error> {
    serde_json::from_value(serde_json::Value::String(text.to_string()))
}

/// [`SubjectRef`] 落库唯一编码：`batch:<id>` / `asset:<id>`。
///
/// 全 crate 统一口径：ownership_states / custody_states / transfers /
/// lifecycle_events / notes.asset_ref 的 subject 列共用本编码，禁止各仓储
/// 自行拼接导致格式漂移。
pub(crate) fn encode_subject(subject: &vg_domain::shared::SubjectRef) -> String {
    match subject {
        vg_domain::shared::SubjectRef::Batch(id) => format!("batch:{id}"),
        vg_domain::shared::SubjectRef::Asset(id) => format!("asset:{id}"),
    }
}

/// 从库中文本还原 [`SubjectRef`]；非法前缀/格式说明存储层数据损坏，
/// 报 Storage 错误（[`encode_subject`] 的逆函数）。
pub(crate) fn decode_subject(
    raw: &str,
) -> Result<vg_domain::shared::SubjectRef, vg_domain::shared::DomainError> {
    use vg_domain::shared::{AssetId, BatchId, DomainError, SubjectRef};
    let (kind, id) = raw
        .split_once(':')
        .ok_or_else(|| DomainError::Storage(format!("库中主体 `{raw}` 非法：缺少类型前缀")))?;
    match kind {
        "batch" => Ok(SubjectRef::Batch(BatchId::new(id))),
        "asset" => Ok(SubjectRef::Asset(AssetId::new(id))),
        other => Err(DomainError::Storage(format!(
            "库中主体 `{raw}` 非法：未知类型前缀 `{other}`"
        ))),
    }
}

/// 判定 sqlx 错误是否为唯一约束违例（SQLSTATE 23505）。
///
/// 说明：仓储主路径用 `ON CONFLICT DO NOTHING` + 行计数承载幂等/冲突
/// （唯一约束违例会中止整个 PostgreSQL 事务，见 ownership_repo 文档）；
/// 本判定仅供测试断言约束本身（如 transfers.intent_id UNIQUE）。
#[cfg(test)]
pub(crate) fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(|d| d.code().as_deref() == Some("23505"))
}

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
        "approvals",
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
        "ledger_state",
        "lifecycle_events",
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

        // 抽查：CHECK 白名单与谱系 op 合法值。全部在事务内执行并回滚，
        // 保证测试幂等可重跑。非法值用例先插入合法产品/父批次，确保
        // 失败只能归因于 CHECK 本身（排除 FK 混淆），并以错误文本断言语义。
        let mut tx = pool.begin().await.expect("开启事务应成功");
        sqlx::query("INSERT INTO products (id, category, metadata_hash, created_at) VALUES ('t-prod', 'milk', decode(repeat('ab', 32), 'hex'), now())")
            .execute(&mut *tx)
            .await
            .expect("插入产品应成功");
        sqlx::query("INSERT INTO batches (id, product_id, quantity, unit, produced_at, producer, state) VALUES ('t-parent', 't-prod', 1, 'kg', now(), 't-did', 'created')")
            .execute(&mut *tx)
            .await
            .expect("插入父批次应成功");

        // 非法 lifecycle 状态：产品/批次前置已满足，失败必为 CHECK。
        // 错误会中止外层事务，故用 SAVEPOINT 包裹后回滚到该点。
        sqlx::query("SAVEPOINT neg_state")
            .execute(&mut *tx)
            .await
            .expect("建立 savepoint 应成功");
        let bad_state = sqlx::query(
            "INSERT INTO batches (id, product_id, quantity, unit, produced_at, producer, state) \
             VALUES ('t-bad', 't-prod', 1, 'kg', now(), 't-did', 'teleported')",
        )
        .execute(&mut *tx)
        .await;
        sqlx::query("ROLLBACK TO SAVEPOINT neg_state")
            .execute(&mut *tx)
            .await
            .expect("回滚 savepoint 应成功");
        match bad_state {
            Err(e) => assert!(
                e.to_string().contains("check constraint"),
                "非法 lifecycle 状态应违反 CHECK，实际错误：{e}"
            ),
            Ok(_) => panic!("非法 lifecycle 状态应被拒绝"),
        }

        // 合法谱系 op（split/merge/transform，LineageOp 全集）逐一入库
        for (child, op) in [
            ("t-split", "split"),
            ("t-merge", "merge"),
            ("t-transform", "transform"),
        ] {
            sqlx::query("INSERT INTO batches (id, product_id, quantity, unit, produced_at, producer, state) VALUES ($1, 't-prod', 1, 'kg', now(), 't-did', 'created')")
                .bind(child)
                .execute(&mut *tx)
                .await
                .expect("插入子批次应成功");
            sqlx::query(
                "INSERT INTO batch_lineage (parent, child, op) VALUES ('t-parent', $1, $2)",
            )
            .bind(child)
            .bind(op)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| panic!("合法谱系 op {op} 应通过 CHECK：{e}"));
        }
        // 非法 op：父子批次均已存在（避免 PK/FK 混淆），失败必为 CHECK；
        // 同样以 SAVEPOINT 包裹以继续外层事务
        sqlx::query("INSERT INTO batches (id, product_id, quantity, unit, produced_at, producer, state) VALUES ('t-op-bad', 't-prod', 1, 'kg', now(), 't-did', 'created')")
            .execute(&mut *tx)
            .await
            .expect("插入用例批次应成功");
        sqlx::query("SAVEPOINT neg_op")
            .execute(&mut *tx)
            .await
            .expect("建立 savepoint 应成功");
        let bad_op = sqlx::query(
            "INSERT INTO batch_lineage (parent, child, op) VALUES ('t-parent', 't-op-bad', 'fission')",
        )
        .execute(&mut *tx)
        .await;
        sqlx::query("ROLLBACK TO SAVEPOINT neg_op")
            .execute(&mut *tx)
            .await
            .expect("回滚 savepoint 应成功");
        match bad_op {
            Err(e) => assert!(
                e.to_string().contains("check constraint"),
                "非法谱系 op 应违反 CHECK，实际错误：{e}"
            ),
            Ok(_) => panic!("非法谱系 op 应被拒绝"),
        }
        tx.rollback().await.expect("回滚应成功");
    }
}
