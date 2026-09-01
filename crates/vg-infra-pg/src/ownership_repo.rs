//! 所有权/保管仓储：PostgreSQL 实现（Context 事务模式，与 identity 同款）。
//!
//! [`PgOwnershipRepo`] 实现 [`OwnershipRepository`]。所有权与保管两套档案
//! 落在不同表（ownership_states / custody_states），互不触碰——存储结构
//! 本身承载"所有权/保管分离"的领域不变量。
//!
//! 写路径结论：**端口有 [`record_transfer`]**（领域侧 transfer() 返回
//! [`TransferRecord`]，应用层 get → transfer → save → record_transfer 组装，
//! Task 20），transfers 表由本方法落库，`record_id` 唯一约束承载按
//! record.id 的幂等；history 只查表（ORDER BY serial ASC = 追加序）。
//!
//! [`CustodyReason`] 只存在于领域事件（CustodyChanged，Task 17 outbox 落
//! domain_events），custody_states 表不存 reason——本仓储仅持久化
//! custodian / since。

use async_trait::async_trait;
use sqlx::Row;

use vg_domain::ownership::ports::OwnershipRepository;
use vg_domain::ownership::{CustodyState, OwnershipState, TransferRecord};
use vg_domain::shared::{DomainError, SubjectRef};

use crate::{decode_subject, encode_subject, parse_did, storage};

/// 所有权/保管上下文的 PostgreSQL 仓储。
#[derive(Debug, Default, Clone, Copy)]
pub struct PgOwnershipRepo;

#[async_trait]
impl OwnershipRepository for PgOwnershipRepo {
    type Context = sqlx::Transaction<'static, sqlx::Postgres>;

    /// 初始化所有权档案：同主体已存在 → [`DomainError::AlreadyExists`]
    /// （合约 `require(ownerDid == bytes32(0), "owner exists")` 的存储层落地）。
    ///
    /// 用 `ON CONFLICT DO NOTHING` + 0 行命中判定，而非裸 INSERT 等
    /// 23505：唯一约束违例会中止整个 PostgreSQL 事务（25P02），后续命令
    /// 全部失效；应用层需在同一 ctx 内继续读写的场景（重复建档 → 回读
    /// 原档案）不能容忍事务被打断。
    async fn init_owner(
        &self,
        ctx: &mut Self::Context,
        state: &OwnershipState,
    ) -> Result<(), DomainError> {
        let result = sqlx::query(
            "INSERT INTO ownership_states \
                 (subject, owner, acquired_at, transfer_count, c2c_count) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (subject) DO NOTHING",
        )
        .bind(encode_subject(&state.subject))
        .bind(state.owner.as_str())
        .bind(state.acquired_at)
        .bind(state.transfer_count as i64)
        .bind(state.c2c_count as i64)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        if result.rows_affected() == 0 {
            // 冲突只可能来自 subject PK：一个主体至多一条所有权档案
            return Err(DomainError::AlreadyExists);
        }
        Ok(())
    }

    /// 按主体查询所有权；不存在返回 `Ok(None)`。
    async fn get(
        &self,
        ctx: &mut Self::Context,
        subject: &SubjectRef,
    ) -> Result<Option<OwnershipState>, DomainError> {
        let row = sqlx::query(
            "SELECT subject, owner, acquired_at, transfer_count, c2c_count \
             FROM ownership_states WHERE subject = $1",
        )
        .bind(encode_subject(subject))
        .fetch_optional(&mut **ctx)
        .await
        .map_err(storage)?;
        row.map(|r| {
            let transfer_count: i64 = r.get("transfer_count");
            let c2c_count: i64 = r.get("c2c_count");
            Ok(OwnershipState {
                subject: decode_subject(r.get("subject"))?,
                owner: parse_did(r.get("owner"))?,
                acquired_at: r.get("acquired_at"),
                transfer_count: u32::try_from(transfer_count).map_err(|_| {
                    DomainError::Storage(format!(
                        "库中 transfer_count `{transfer_count}` 超出 u32 口径"
                    ))
                })?,
                c2c_count: u32::try_from(c2c_count)
                    .map_err(|_| DomainError::Storage(format!("库中 c2c_count `{c2c_count}` 超出 u32 口径")))?,
            })
        })
        .transpose()
    }

    /// 整体替换保存所有权（转移写路径 get → transfer → save 的落库端）。
    async fn save(&self, ctx: &mut Self::Context, state: &OwnershipState) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO ownership_states \
                 (subject, owner, acquired_at, transfer_count, c2c_count) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (subject) DO UPDATE SET \
                 owner = EXCLUDED.owner, \
                 acquired_at = EXCLUDED.acquired_at, \
                 transfer_count = EXCLUDED.transfer_count, \
                 c2c_count = EXCLUDED.c2c_count",
        )
        .bind(encode_subject(&state.subject))
        .bind(state.owner.as_str())
        .bind(state.acquired_at)
        .bind(state.transfer_count as i64)
        .bind(state.c2c_count as i64)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// 记录保管状态（upsert：无则建档，有则覆盖 custodian/since）。
    ///
    /// 与所有权存储完全独立；reason 不落本表（见模块文档）。
    async fn update_custody(
        &self,
        ctx: &mut Self::Context,
        custody: &CustodyState,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO custody_states (subject, custodian, since) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (subject) DO UPDATE SET \
                 custodian = EXCLUDED.custodian, \
                 since = EXCLUDED.since",
        )
        .bind(encode_subject(&custody.subject))
        .bind(custody.custodian.as_str())
        .bind(custody.since)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// 追加转移审计记录：`record_id` 唯一约束 + `ON CONFLICT DO NOTHING`
    /// 承载按 `record.id` 的幂等（同 id 重复提交不产生新条目）。
    async fn record_transfer(
        &self,
        ctx: &mut Self::Context,
        record: &TransferRecord,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO transfers \
                 (record_id, subject, from_did, to_did, c2c, at, \
                  transfer_count, c2c_count, intent_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL) \
             ON CONFLICT (record_id) WHERE record_id IS NOT NULL DO NOTHING",
        )
        .bind(&record.id)
        .bind(encode_subject(&record.subject))
        .bind(record.from.as_str())
        .bind(record.to.as_str())
        .bind(record.c2c)
        .bind(record.at)
        .bind(record.transfer_count as i64)
        .bind(record.c2c_count as i64)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// 按主体回放转移审计：`ORDER BY serial ASC`（bigserial 追加序契约，
    /// 与领域"按追加序返回"一致）。仅还原具 `record_id` 的完整
    /// [`TransferRecord`] 行（record_transfer 写入侧）。
    async fn history(
        &self,
        ctx: &mut Self::Context,
        subject: &SubjectRef,
    ) -> Result<Vec<TransferRecord>, DomainError> {
        let rows = sqlx::query(
            "SELECT record_id, subject, from_did, to_did, c2c, at, \
                    transfer_count, c2c_count \
             FROM transfers WHERE subject = $1 AND record_id IS NOT NULL \
             ORDER BY serial ASC",
        )
        .bind(encode_subject(subject))
        .fetch_all(&mut **ctx)
        .await
        .map_err(storage)?;
        rows.iter()
            .map(|r| {
                let transfer_count: i64 = r.get("transfer_count");
                let c2c_count: i64 = r.get("c2c_count");
                Ok(TransferRecord {
                    id: r.get("record_id"),
                    subject: decode_subject(r.get("subject"))?,
                    from: parse_did(r.get("from_did"))?,
                    to: parse_did(r.get("to_did"))?,
                    c2c: r.get("c2c"),
                    at: r.get("at"),
                    transfer_count: u32::try_from(transfer_count).map_err(|_| {
                        DomainError::Storage(format!(
                            "库中 transfer_count `{transfer_count}` 超出 u32 口径"
                        ))
                    })?,
                    c2c_count: u32::try_from(c2c_count).map_err(|_| {
                        DomainError::Storage(format!(
                            "库中 c2c_count `{c2c_count}` 超出 u32 口径"
                        ))
                    })?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::is_unique_violation;
    use chrono::{DateTime, TimeZone, Utc};
    use vg_domain::shared::{AssetId, BatchId, Did};

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 0, 0, 0).unwrap()
    }

    fn later_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap()
    }

    fn batch_subject(id: &str) -> SubjectRef {
        SubjectRef::Batch(BatchId::new(id))
    }

    fn asset_subject(id: &str) -> SubjectRef {
        SubjectRef::Asset(AssetId::new(id))
    }

    fn alice() -> Did {
        Did::parse("did:vg:user:alice-16").unwrap()
    }

    fn bob() -> Did {
        Did::parse("did:vg:user:bob-16").unwrap()
    }

    fn carol() -> Did {
        Did::parse("did:vg:user:carol-16").unwrap()
    }

    /// init_owner：建档 → get 往返（双主体类型）；同主体二次 → AlreadyExists；
    /// save 整体替换后 owner/计数/acquired_at 全部更新。
    #[sqlx::test]
    async fn init_get_save_and_already_exists(pool: sqlx::PgPool) {
        let repo = PgOwnershipRepo;
        let mut tx = pool.begin().await.unwrap();

        // 空库：get None
        assert!(repo.get(&mut tx, &batch_subject("b-own")).await.unwrap().is_none());

        // 建档（batch 主体）→ 往返
        let state = OwnershipState::initialize(batch_subject("b-own"), alice(), fixed_time());
        repo.init_owner(&mut tx, &state).await.expect("建档应成功");
        assert_eq!(repo.get(&mut tx, &state.subject).await.unwrap(), Some(state.clone()));

        // 同主体二次建档（asset 主体同样验证）→ AlreadyExists（合约 "owner exists"）
        let dup = OwnershipState::initialize(batch_subject("b-own"), bob(), later_time());
        let err = repo
            .init_owner(&mut tx, &dup)
            .await
            .expect_err("重复建档必须被拒绝");
        assert!(matches!(err, DomainError::AlreadyExists), "{err:?}");
        // 原档案不被覆盖
        assert_eq!(repo.get(&mut tx, &state.subject).await.unwrap().unwrap().owner, alice());

        let asset_state = OwnershipState::initialize(asset_subject("a-own"), carol(), fixed_time());
        repo.init_owner(&mut tx, &asset_state).await.unwrap();
        assert_eq!(
            repo.get(&mut tx, &asset_state.subject).await.unwrap(),
            Some(asset_state)
        );

        // save 整体替换：转移后 owner/计数/acquired_at 全落库
        let mut moved = state.clone();
        let record = moved.transfer(&bob(), true, later_time()).unwrap();
        repo.save(&mut tx, &moved).await.unwrap();
        repo.record_transfer(&mut tx, &record).await.unwrap();
        let stored = repo.get(&mut tx, &state.subject).await.unwrap().unwrap();
        assert_eq!(stored.owner, bob());
        assert_eq!((stored.transfer_count, stored.c2c_count), (1, 1));
        assert_eq!(stored.acquired_at, later_time());

        tx.commit().await.unwrap();
    }

    /// update_custody upsert：建档 → 覆盖 custodian/since；不经端口读回
    /// （端口只暴露写入侧），以裸 SQL 验证落库值。
    #[sqlx::test]
    async fn update_custody_upserts_custodian_and_since(pool: sqlx::PgPool) {
        let repo = PgOwnershipRepo;
        let mut tx = pool.begin().await.unwrap();

        let subject = asset_subject("a-cust");
        repo.update_custody(
            &mut tx,
            &CustodyState::new(subject.clone(), alice(), fixed_time()),
        )
        .await
        .expect("建档保管应成功");

        // 覆盖：换保管人 + 刷新 since
        repo.update_custody(
            &mut tx,
            &CustodyState::new(subject.clone(), bob(), later_time()),
        )
        .await
        .expect("覆盖保管应成功");

        let row = sqlx::query("SELECT custodian, since FROM custody_states WHERE subject = $1")
            .bind(encode_subject(&subject))
            .fetch_one(&mut *tx)
            .await
            .expect("保管档案应存在且仅一条");
        let custodian: String = row.get("custodian");
        let since: DateTime<Utc> = row.get("since");
        assert_eq!(custodian, bob().to_string());
        assert_eq!(since, later_time());

        tx.commit().await.unwrap();
    }

    /// record_transfer + history：按追加序（serial）回放、幂等去重、
    /// 完整字段往返；无关主体互不可见。
    #[sqlx::test]
    async fn record_transfer_history_and_idempotency(pool: sqlx::PgPool) {
        let repo = PgOwnershipRepo;
        let mut tx = pool.begin().await.unwrap();

        let subject = batch_subject("b-hist");
        let mut state = OwnershipState::initialize(subject.clone(), alice(), fixed_time());
        repo.init_owner(&mut tx, &state).await.unwrap();

        let r1 = state.transfer(&bob(), false, fixed_time()).unwrap();
        let r2 = state.transfer(&carol(), true, later_time()).unwrap();
        repo.record_transfer(&mut tx, &r1).await.unwrap();
        repo.record_transfer(&mut tx, &r2).await.unwrap();
        // 幂等：同 id 重复提交 Ok 且不新增
        repo.record_transfer(&mut tx, &r1)
            .await
            .expect("重复提交应幂等成功");

        let history = repo.history(&mut tx, &subject).await.unwrap();
        assert_eq!(history, vec![r1.clone(), r2.clone()], "按追加序完整回放");
        assert_eq!((history[1].transfer_count, history[1].c2c_count), (2, 1));

        assert!(
            repo.history(&mut tx, &batch_subject("b-other"))
                .await
                .unwrap()
                .is_empty(),
            "无关主体互不可见"
        );

        tx.commit().await.unwrap();
    }

    /// 计划重点：transfers.intent_id UNIQUE——同 intent 二次插入报
    /// SQLSTATE 23505（应用层写路径的幂等守卫，裸 SQL 验证约束本身）。
    #[sqlx::test]
    async fn transfers_intent_id_unique_rejects_duplicates(pool: sqlx::PgPool) {
        let mut tx = pool.begin().await.unwrap();

        sqlx::query(
            "INSERT INTO transfers (subject, from_did, to_did, c2c, at, intent_id) \
             VALUES ('batch:b-iu', 'did:vg:user:a', 'did:vg:user:b', false, now(), 'it-dup')",
        )
        .execute(&mut *tx)
        .await
        .expect("首次插入应成功");

        let dup = sqlx::query(
            "INSERT INTO transfers (subject, from_did, to_did, c2c, at, intent_id) \
             VALUES ('batch:b-iu', 'did:vg:user:b', 'did:vg:user:c', true, now(), 'it-dup')",
        )
        .execute(&mut *tx)
        .await;
        match dup {
            Err(e) => assert!(
                is_unique_violation(&e),
                "intent_id 重复应为唯一约束违例（23505），实际：{e}"
            ),
            Ok(_) => panic!("intent_id 重复插入必须被拒绝"),
        }

        tx.rollback().await.unwrap();
    }
}
