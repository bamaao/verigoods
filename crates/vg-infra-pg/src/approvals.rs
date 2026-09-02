//! 审批待办存储：PostgreSQL 实现（Task 19，`approvals` 表，0006 迁移）。
//!
//! L3/L4 风险动作在管道推进到 `Approved` 之前须经人工审批：handler 判定
//! [`AwaitingApproval`] 时由 IntentEngine 落一条未决行，`approve` 路径经
//! [`PgApprovalsStore::mark_decided`] 一次性写入决策（`decided_by/decided_at`
//! 写入后不可再变）。Context 事务模式与其余仓储同款。

use chrono::{DateTime, Utc};
use sqlx::Row;

use vg_domain::shared::{DomainError, IntentId};

/// 审批待办行（读侧载体）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRow {
    /// 关联意图 ID。
    pub intent_id: String,
    /// 要求的审批人 SubjectKind（snake_case，如 `regulator`）。
    pub required_role: String,
    /// 审批人 DID；`None` = 未决。
    pub decided_by: Option<String>,
    /// 决策时刻；`None` = 未决。
    pub decided_at: Option<DateTime<Utc>>,
}

impl ApprovalRow {
    /// 是否仍未决策。
    pub fn is_undecided(&self) -> bool {
        self.decided_by.is_none()
    }
}

/// 审批待办的 PostgreSQL 存储（Context 事务模式）。
#[derive(Debug, Default, Clone, Copy)]
pub struct PgApprovalsStore;

impl PgApprovalsStore {
    /// 落一条**未决**审批待办：`ON CONFLICT (intent_id) DO NOTHING`。
    ///
    /// 已存在待办行不覆盖（保持首次写入的 required_role）；已决策行更不可
    /// 覆盖（审批结论不可篡改）。重复 upsert 是 no-op 而非冲突——审批门
    /// 挂起语义天然幂等。
    pub async fn upsert_undecided(
        &self,
        ctx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        intent_id: &IntentId,
        required_role: &str,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO approvals (intent_id, required_role) VALUES ($1, $2) \
             ON CONFLICT (intent_id) DO NOTHING",
        )
        .bind(intent_id.as_ref())
        .bind(required_role)
        .execute(&mut **ctx)
        .await
        .map_err(crate::storage)?;
        Ok(())
    }

    /// 按意图 ID 查找审批待办；不存在时返回 `Ok(None)`。
    pub async fn find(
        &self,
        ctx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        intent_id: &IntentId,
    ) -> Result<Option<ApprovalRow>, DomainError> {
        let row = sqlx::query(
            "SELECT intent_id, required_role, decided_by, decided_at \
             FROM approvals WHERE intent_id = $1",
        )
        .bind(intent_id.as_ref())
        .fetch_optional(&mut **ctx)
        .await
        .map_err(crate::storage)?;
        Ok(row.map(|r| ApprovalRow {
            intent_id: r.get("intent_id"),
            required_role: r.get("required_role"),
            decided_by: r.get("decided_by"),
            decided_at: r.get("decided_at"),
        }))
    }

    /// 写入决策：`UPDATE ... WHERE intent_id = $1 AND decided_by IS NULL`。
    ///
    /// 0 行命中的两种成因：意图无审批待办行 / 该行**已决策**。后者是
    /// `approve` 的幂等信号——调用方先 [`PgApprovalsStore::find`] 查行，
    /// 已决策走幂等返回而非报错；未对已决策行二次 mark 报
    /// [`DomainError::AlreadyExists`]（防静默覆盖审批结论）。
    pub async fn mark_decided(
        &self,
        ctx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        intent_id: &IntentId,
        decided_by: &vg_domain::shared::Did,
        at: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let result = sqlx::query(
            "UPDATE approvals SET decided_by = $2, decided_at = $3 \
             WHERE intent_id = $1 AND decided_by IS NULL",
        )
        .bind(intent_id.as_ref())
        .bind(decided_by.as_str())
        .bind(at)
        .execute(&mut **ctx)
        .await
        .map_err(crate::storage)?;
        if result.rows_affected() == 0 {
            return Err(DomainError::AlreadyExists);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use vg_domain::intent::ports::IntentRepository;
    use vg_domain::intent::{Intent, IntentAction};
    use vg_domain::shared::Did;

    /// 前置意图行（approvals 的 FK 依赖）。
    async fn seed_intent(tx: &mut sqlx::Transaction<'static, sqlx::Postgres>, id: &str) {
        let intent = Intent::new(
            vg_domain::shared::IntentId::new(id),
            IntentAction::TransferProduct,
            Did::parse("did:vg:user:ent-19").unwrap(),
            None,
            serde_json::json!({"subject": "batch:bt-19"}),
            1,
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
        )
        .expect("样本构造应成功");
        crate::PgIntentRepository
            .insert(tx, &intent)
            .await
            .expect("前置意图应插入成功");
    }

    /// 往返：upsert 未决 → find 还原；无行 find → None。
    #[sqlx::test]
    async fn upsert_find_roundtrip(pool: sqlx::PgPool) {
        let store = PgApprovalsStore;
        let mut tx = pool.begin().await.unwrap();
        seed_intent(&mut tx, "it-ap-1").await;

        let id = vg_domain::shared::IntentId::new("it-ap-1");
        store
            .upsert_undecided(&mut tx, &id, "regulator")
            .await
            .expect("落未决待办应成功");
        let row = store
            .find(&mut tx, &id)
            .await
            .expect("查询应成功")
            .expect("刚 upsert 的行应存在");
        assert_eq!(row.intent_id, "it-ap-1");
        assert_eq!(row.required_role, "regulator");
        assert!(row.is_undecided(), "初始行应为未决");
        assert_eq!(row.decided_by, None);
        assert_eq!(row.decided_at, None);

        assert!(
            store
                .find(&mut tx, &vg_domain::shared::IntentId::new("it-none"))
                .await
                .unwrap()
                .is_none(),
            "无待办行应返回 None"
        );
        tx.commit().await.unwrap();
    }

    /// 未决覆盖保护：二次 upsert 不同角色是 no-op，首行 required_role 不变。
    #[sqlx::test]
    async fn upsert_does_not_overwrite_existing(pool: sqlx::PgPool) {
        let store = PgApprovalsStore;
        let mut tx = pool.begin().await.unwrap();
        seed_intent(&mut tx, "it-ap-2").await;

        let id = vg_domain::shared::IntentId::new("it-ap-2");
        store
            .upsert_undecided(&mut tx, &id, "regulator")
            .await
            .unwrap();
        // 二次 upsert（角色不同）应为 no-op
        store
            .upsert_undecided(&mut tx, &id, "enterprise")
            .await
            .unwrap();
        let row = store.find(&mut tx, &id).await.unwrap().unwrap();
        assert_eq!(row.required_role, "regulator", "首行角色不得被覆盖");
        tx.commit().await.unwrap();
    }

    /// 已决策行：mark 成功写入 decided_by/at；二次 mark → AlreadyExists；
    /// 已决策后 upsert 仍不得覆盖。
    #[sqlx::test]
    async fn mark_decided_is_one_shot(pool: sqlx::PgPool) {
        let store = PgApprovalsStore;
        let mut tx = pool.begin().await.unwrap();
        seed_intent(&mut tx, "it-ap-3").await;

        let id = vg_domain::shared::IntentId::new("it-ap-3");
        store
            .upsert_undecided(&mut tx, &id, "regulator")
            .await
            .unwrap();

        let approver = Did::parse("did:vg:user:reg-19").unwrap();
        let at = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        store
            .mark_decided(&mut tx, &id, &approver, at)
            .await
            .expect("首次决策应成功");
        let row = store.find(&mut tx, &id).await.unwrap().expect("行应存在");
        assert!(!row.is_undecided());
        assert_eq!(row.decided_by.as_deref(), Some("did:vg:user:reg-19"));
        assert_eq!(row.decided_at, Some(at));

        // 二次 mark：已决策 → AlreadyExists（幂等信号由调用方 find 区分）
        match store.mark_decided(&mut tx, &id, &approver, at).await {
            Err(DomainError::AlreadyExists) => {}
            other => panic!("已决策二次 mark 应报 AlreadyExists，实际：{other:?}"),
        }
        // 已决策后 upsert 不得覆盖决策
        store
            .upsert_undecided(&mut tx, &id, "enterprise")
            .await
            .unwrap();
        let row = store.find(&mut tx, &id).await.unwrap().unwrap();
        assert_eq!(row.required_role, "regulator");
        assert_eq!(row.decided_by.as_deref(), Some("did:vg:user:reg-19"));

        // 无待办行的 intent：mark 0 行 → AlreadyExists（调用方先 find 区分成因）
        match store
            .mark_decided(
                &mut tx,
                &vg_domain::shared::IntentId::new("it-none"),
                &approver,
                at,
            )
            .await
        {
            Err(DomainError::AlreadyExists) => {}
            other => panic!("无待办行 mark 应报 AlreadyExists，实际：{other:?}"),
        }
        tx.commit().await.unwrap();
    }
}
