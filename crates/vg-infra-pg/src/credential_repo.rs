//! 凭证仓储：PostgreSQL 实现（Context 事务模式）。
//!
//! [`PgCredentialRepo`] 实现 [`CredentialRepository`]，`Context` 绑定为
//! `sqlx::Transaction<'static, Postgres>`（与 [`crate::PgIdentityRepo`] 同一约定）。
//! [`vg_domain::credential::ports::CredentialAnchorPort`] 属链层端口
//! （Task 18/26），本 crate 不实现。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;

use vg_domain::credential::ports::CredentialRepository;
use vg_domain::credential::{CredStatus, VerifiableCredential};
use vg_domain::shared::{CredentialId, Did, DomainError, Hash32};

use crate::{enum_from_text, enum_to_text, storage};

/// 凭证聚合的 PostgreSQL 仓储。
#[derive(Debug, Default, Clone, Copy)]
pub struct PgCredentialRepo;

#[async_trait]
impl CredentialRepository for PgCredentialRepo {
    type Context = sqlx::Transaction<'static, sqlx::Postgres>;

    /// 保存凭证。
    ///
    /// `credential_hash` 全局 UNIQUE（落库前不可变契约）：违反唯一约束
    /// （SQLSTATE 23505）映射为 [`DomainError::AlreadyExists`]，
    /// 含按 id 的主键冲突（同 id 二次保存同 hash 亦属"已存在"）。
    async fn save(
        &self,
        ctx: &mut Self::Context,
        vc: &VerifiableCredential,
    ) -> Result<(), DomainError> {
        // sqlx 未启用 json feature：claims 以文本编码后在 SQL 内 cast 为 jsonb
        let claims_text = serde_json::to_string(&vc.claims)
            .map_err(|e| DomainError::Storage(format!("claims 序列化失败：{e}")))?;

        let res = sqlx::query(
            "INSERT INTO credentials \
             (id, issuer, subject, ctype, claims, issued_at, expires_at, status, credential_hash) \
             VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9)",
        )
        .bind(vc.id.as_ref())
        .bind(vc.issuer.as_str())
        .bind(vc.subject.as_str())
        .bind(enum_to_text(&vc.ctype))
        .bind(claims_text)
        .bind(vc.issued_at)
        .bind(vc.expires_at)
        .bind(enum_to_text(&vc.status))
        .bind(vc.credential_hash.as_bytes().as_slice())
        .execute(&mut **ctx)
        .await;

        match res {
            Ok(_) => Ok(()),
            // 唯一约束（credential_hash / id 主键）冲突 → 领域幂等冲突错误
            Err(e)
                if e.as_database_error()
                    .is_some_and(|d| d.is_unique_violation()) =>
            {
                Err(DomainError::AlreadyExists)
            }
            Err(e) => Err(storage(e)),
        }
    }

    /// 按凭证 ID 查找；不存在返回 `Ok(None)`。
    ///
    /// ctype / status 还原经 serde_json roundtrip（`as_str` 字符串 → 枚举），
    /// 与 CHECK 白名单同源，避免手写映射表漂移。
    async fn find(
        &self,
        ctx: &mut Self::Context,
        id: &CredentialId,
    ) -> Result<Option<VerifiableCredential>, DomainError> {
        let row = sqlx::query(
            "SELECT id, issuer, subject, ctype, claims::text AS claims, issued_at, expires_at, status, credential_hash \
             FROM credentials WHERE id = $1",
        )
        .bind(id.as_ref())
        .fetch_optional(&mut **ctx)
        .await
        .map_err(storage)?;
        let Some(row) = row else {
            return Ok(None);
        };
        row_to_vc(&row).map(Some)
    }

    /// 列出某主体的全部凭证；`ORDER BY id` 保证确定性。
    async fn list_by_subject(
        &self,
        ctx: &mut Self::Context,
        subject: &Did,
    ) -> Result<Vec<VerifiableCredential>, DomainError> {
        let rows = sqlx::query(
            "SELECT id, issuer, subject, ctype, claims::text AS claims, issued_at, expires_at, status, credential_hash \
             FROM credentials WHERE subject = $1 ORDER BY id",
        )
        .bind(subject.as_str())
        .fetch_all(&mut **ctx)
        .await
        .map_err(storage)?;

        rows.iter().map(row_to_vc).collect()
    }

    /// 乐观锁式状态更新：仅当当前状态等于 `expected` 时置为 `next`。
    ///
    /// - 更新影响 0 行时先 SELECT 存在性：不存在 → [`DomainError::NotFound`]；
    ///   存在但状态不符 → [`DomainError::InvalidTransition`]（from=实际状态，
    ///   to=期望下一状态，格式与领域层 `transition` 一致：`中文名(snake_case)`）；
    /// - `at` 为状态生效时刻：credentials 表无状态时间列（审计走
    ///   audit_events / 领域事件，Task 16+），此处不落库，仅保留语义。
    async fn update_status(
        &self,
        ctx: &mut Self::Context,
        id: &CredentialId,
        expected: CredStatus,
        next: CredStatus,
        _at: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let result =
            sqlx::query("UPDATE credentials SET status = $1 WHERE id = $2 AND status = $3")
                .bind(enum_to_text(&next))
                .bind(id.as_ref())
                .bind(enum_to_text(&expected))
                .execute(&mut **ctx)
                .await
                .map_err(storage)?;

        if result.rows_affected() == 1 {
            return Ok(());
        }

        // 0 行：区分"不存在"与"状态不符"
        let actual: Option<String> = sqlx::query("SELECT status FROM credentials WHERE id = $1")
            .bind(id.as_ref())
            .fetch_optional(&mut **ctx)
            .await
            .map_err(storage)?
            .map(|r| r.get("status"));

        match actual {
            None => Err(DomainError::NotFound),
            Some(actual) => {
                let actual: CredStatus = enum_from_text(&actual).map_err(|e| {
                    DomainError::Storage(format!("库中 status `{actual}` 非法：{e}"))
                })?;
                Err(DomainError::InvalidTransition {
                    from: format!("{}({})", actual.zh_name(), actual.as_str()),
                    to: format!("{}({})", next.zh_name(), next.as_str()),
                })
            }
        }
    }
}

/// 行 → VC 还原；任何列损坏（非法 DID/枚举/摘要长度）报 Storage 错误。
fn row_to_vc(row: &sqlx::postgres::PgRow) -> Result<VerifiableCredential, DomainError> {
    let ctype: String = row.get("ctype");
    let status: String = row.get("status");
    // claims 列为 jsonb；SQL 侧已 cast 为 text（SELECT claims::text），
    // 未启用 sqlx json feature，故以文本取回后再解析为 JSON
    let claims_text: String = row.get("claims");
    let claims: serde_json::Value = serde_json::from_str(&claims_text)
        .map_err(|e| DomainError::Storage(format!("库中 claims 非法 JSON：{e}")))?;

    let hash: Vec<u8> = row.get("credential_hash");
    let bytes: [u8; 32] = hash
        .try_into()
        .map_err(|_| DomainError::Storage("库中 credential_hash 长度非法".into()))?;

    Ok(VerifiableCredential {
        id: CredentialId::new(row.get::<&str, _>("id")),
        issuer: parse_did(row.get("issuer"))?,
        subject: parse_did(row.get("subject"))?,
        ctype: enum_from_text(&ctype)
            .map_err(|e| DomainError::Storage(format!("库中 ctype `{ctype}` 非法：{e}")))?,
        claims,
        issued_at: row.get("issued_at"),
        expires_at: row.get("expires_at"),
        status: enum_from_text(&status)
            .map_err(|e| DomainError::Storage(format!("库中 status `{status}` 非法：{e}")))?,
        credential_hash: Hash32::from_bytes(bytes),
    })
}

/// 从库中文本还原 DID；解析失败说明存储层数据损坏，报 Storage 错误。
fn parse_did(raw: &str) -> Result<Did, DomainError> {
    Did::parse(raw).map_err(|e| DomainError::Storage(format!("库中 DID `{raw}` 非法：{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use vg_domain::credential::CredentialType;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap()
    }

    fn issuer() -> Did {
        Did::parse("did:vg:user:ent-iss").unwrap()
    }

    fn subject() -> Did {
        Did::parse("did:vg:batch:b-15").unwrap()
    }

    fn sample_vc(id: &str) -> VerifiableCredential {
        VerifiableCredential::new(
            CredentialId::new(id),
            issuer(),
            subject(),
            CredentialType::ColdChain,
            serde_json::json!({"temp_range": "2~8℃", "log": [{"t": 1, "c": 4}]}),
            fixed_time(),
            Some(fixed_time() + chrono::Duration::days(365)),
        )
        .expect("样例凭证应构造成功")
    }

    /// save → find 深相等往返：claims jsonb（含嵌套/数组/非 ASCII）、
    /// expires_at Some 与 None、不同 ctype、非 Valid 状态；不存在 → None。
    #[sqlx::test]
    async fn save_find_roundtrip(pool: sqlx::PgPool) {
        let repo = PgCredentialRepo;
        let mut tx = pool.begin().await.unwrap();

        let vc = sample_vc("vc-c-001");
        repo.save(&mut tx, &vc).await.expect("保存应成功");
        let found = repo
            .find(&mut tx, &vc.id)
            .await
            .expect("查询应成功")
            .expect("刚保存的凭证应能查到");
        assert_eq!(found, vc);

        // expires_at = None + 另一 ctype 抽查（12 类中的第 2 类）
        let eternal = VerifiableCredential::new(
            CredentialId::new("vc-c-002"),
            issuer(),
            subject(),
            CredentialType::Ownership,
            serde_json::json!({"asset": "a-15"}),
            fixed_time(),
            None,
        )
        .unwrap();
        repo.save(&mut tx, &eternal).await.unwrap();
        let found = repo.find(&mut tx, &eternal.id).await.unwrap().unwrap();
        assert_eq!(found, eternal);
        assert_eq!(found.expires_at, None);

        // 非 Valid 状态同样可持久化回读
        let mut suspended = sample_vc("vc-c-003");
        suspended
            .transition(CredStatus::Suspended, &issuer(), fixed_time())
            .unwrap();
        repo.save(&mut tx, &suspended).await.unwrap();
        let found = repo.find(&mut tx, &suspended.id).await.unwrap().unwrap();
        assert_eq!(found.status, CredStatus::Suspended);
        assert_eq!(found, suspended);

        let missing = repo
            .find(&mut tx, &CredentialId::new("vc-nope"))
            .await
            .unwrap();
        assert!(missing.is_none());

        tx.commit().await.unwrap();
    }

    /// 相同 credential_hash 二次保存 → AlreadyExists（不可变承诺契约）。
    #[sqlx::test]
    async fn duplicate_hash_save_fails_with_already_exists(pool: sqlx::PgPool) {
        let repo = PgCredentialRepo;
        let mut tx = pool.begin().await.unwrap();

        let vc = sample_vc("vc-dup");
        repo.save(&mut tx, &vc).await.expect("首次保存应成功");

        let err = repo.save(&mut tx, &vc).await.expect_err("重复保存必须报错");
        assert!(
            matches!(err, DomainError::AlreadyExists),
            "实际错误：{err:?}"
        );

        tx.commit().await.unwrap();
    }

    /// list_by_subject：只含本人凭证且按 id 有序。
    #[sqlx::test]
    async fn list_by_subject_filters_and_orders(pool: sqlx::PgPool) {
        let repo = PgCredentialRepo;
        let mut tx = pool.begin().await.unwrap();

        for id in ["vc-b", "vc-a", "vc-c"] {
            let mut vc = sample_vc(id);
            vc.id = CredentialId::new(id);
            repo.save(&mut tx, &vc).await.unwrap();
        }
        // 其他主体的凭证
        let mut other = sample_vc("vc-x");
        other.subject = Did::parse("did:vg:batch:b-other").unwrap();
        repo.save(&mut tx, &other).await.unwrap();

        let listed = repo.list_by_subject(&mut tx, &subject()).await.unwrap();
        let ids: Vec<&str> = listed.iter().map(|vc| vc.id.as_ref()).collect();
        assert_eq!(ids, vec!["vc-a", "vc-b", "vc-c"], "应只含本人且按 id 有序");

        tx.commit().await.unwrap();
    }

    /// update_status：合法迁移成功；终态迁出 → InvalidTransition；
    /// 不存在 → NotFound。二次 revoke 场景（Revoked→Suspended）必须失败。
    #[sqlx::test]
    async fn update_status_optimistic_checks(pool: sqlx::PgPool) {
        let repo = PgCredentialRepo;
        let mut tx = pool.begin().await.unwrap();

        let vc = sample_vc("vc-st");
        repo.save(&mut tx, &vc).await.unwrap();
        let id = vc.id.clone();

        // Valid → Suspended → Valid（恢复路径）
        repo.update_status(
            &mut tx,
            &id,
            CredStatus::Valid,
            CredStatus::Suspended,
            fixed_time(),
        )
        .await
        .expect("Valid→Suspended 应成功");
        let cur = repo.find(&mut tx, &id).await.unwrap().unwrap();
        assert_eq!(cur.status, CredStatus::Suspended);
        repo.update_status(
            &mut tx,
            &id,
            CredStatus::Suspended,
            CredStatus::Valid,
            fixed_time(),
        )
        .await
        .expect("Suspended→Valid 应成功");

        // Valid → Revoked 成功；二次 revoke（expected 仍为 Valid）→ InvalidTransition：
        // 实际状态已是 revoked，与乐观检查的 expected 不符（from=实际状态、to=期望下一状态）
        repo.update_status(
            &mut tx,
            &id,
            CredStatus::Valid,
            CredStatus::Revoked,
            fixed_time(),
        )
        .await
        .expect("Valid→Revoked 应成功");
        let err = repo
            .update_status(
                &mut tx,
                &id,
                CredStatus::Valid,
                CredStatus::Revoked,
                fixed_time(),
            )
            .await
            .expect_err("二次 revoke 必须失败（expected 与实际不符）");
        match err {
            DomainError::InvalidTransition { from, to } => {
                assert_eq!(from, "已撤销(revoked)", "from 应为实际状态：{from}");
                assert_eq!(to, "已撤销(revoked)");
            }
            other => panic!("应为 InvalidTransition，实际：{other:?}"),
        }

        // 不存在的凭证 → NotFound
        let err = repo
            .update_status(
                &mut tx,
                &CredentialId::new("vc-ghost"),
                CredStatus::Valid,
                CredStatus::Expired,
                fixed_time(),
            )
            .await
            .expect_err("不存在的凭证必须报 NotFound");
        assert!(matches!(err, DomainError::NotFound), "实际错误：{err:?}");

        tx.commit().await.unwrap();
    }
}
