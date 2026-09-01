//! 身份仓储：PostgreSQL 实现（Context 事务模式）。
//!
//! [`PgIdentityRepo`] 实现 [`IdentityRepository`]，`Context` 绑定为
//! `sqlx::Transaction<'static, Postgres>`——由 application 层开启事务并
//! 经 `&mut` 注入，仓储自身不管理事务生命周期（提交/回滚归编排方）。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;

use vg_domain::identity::ports::IdentityRepository;
use vg_domain::identity::{Capability, DidDocument, VerificationMethod};
use vg_domain::shared::{Did, DomainError, Hash32};

use crate::{enum_from_text, enum_to_text, parse_did, storage};

/// 身份聚合的 PostgreSQL 仓储。
#[derive(Debug, Default, Clone, Copy)]
pub struct PgIdentityRepo;

#[async_trait]
impl IdentityRepository for PgIdentityRepo {
    type Context = sqlx::Transaction<'static, sqlx::Postgres>;

    /// 保存或整体替换 DID 文档（按 `doc.did` 幂等）。
    ///
    /// 语义：
    /// - `dids` 行 ON CONFLICT 更新 kind/parent/jurisdiction；
    ///   **`created_at` 保留首次值**（创建时间不可变，入参时间戳被忽略）；
    /// - 验证方法为**全量状态同步**：文档代表该主体的完整方法集，
    ///   不在文档中的方法被 DELETE（含撤销语义——撤销即从集合移除或置 revoked）。
    async fn save_document(
        &self,
        ctx: &mut Self::Context,
        doc: &DidDocument,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO dids (id, kind, parent_did, jurisdiction, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (id) DO UPDATE SET \
                 kind = EXCLUDED.kind, \
                 parent_did = EXCLUDED.parent_did, \
                 jurisdiction = EXCLUDED.jurisdiction",
        )
        .bind(doc.did.as_str())
        .bind(enum_to_text(&doc.kind))
        .bind(doc.parent.as_ref().map(Did::as_str))
        .bind(&doc.jurisdiction)
        .bind(doc.created_at)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;

        for m in &doc.methods {
            sqlx::query(
                "INSERT INTO verification_methods (did, method_id, key_type, public_key, revoked) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (did, method_id) DO UPDATE SET \
                     key_type = EXCLUDED.key_type, \
                     public_key = EXCLUDED.public_key, \
                     revoked = EXCLUDED.revoked",
            )
            .bind(doc.did.as_str())
            .bind(&m.id)
            .bind(enum_to_text(&m.key_type))
            .bind(m.public_key.as_bytes().as_slice())
            .bind(m.revoked)
            .execute(&mut **ctx)
            .await
            .map_err(storage)?;
        }

        // 全量同步：清除文档中不再存在的方法（空数组时 `<> ALL('{}')` 恒真，清空全部）
        let keep: Vec<&str> = doc.methods.iter().map(|m| m.id.as_str()).collect();
        sqlx::query("DELETE FROM verification_methods WHERE did = $1 AND method_id <> ALL($2)")
            .bind(doc.did.as_str())
            .bind(keep)
            .execute(&mut **ctx)
            .await
            .map_err(storage)?;
        Ok(())
    }

    /// 按 DID 查找文档；不存在返回 `Ok(None)`。
    ///
    /// 方法列表 `ORDER BY method_id` 稳定排序（审查既定）：
    /// [`DidDocument::active_pubkey`] 依赖 Vec 顺序，必须保证确定性。
    async fn find_document(
        &self,
        ctx: &mut Self::Context,
        did: &Did,
    ) -> Result<Option<DidDocument>, DomainError> {
        let Some(did_row) = sqlx::query(
            "SELECT id, kind, parent_did, jurisdiction, created_at FROM dids WHERE id = $1",
        )
        .bind(did.as_str())
        .fetch_optional(&mut **ctx)
        .await
        .map_err(storage)?
        else {
            return Ok(None);
        };

        let kind: String = did_row.get("kind");
        let parent: Option<String> = did_row.get("parent_did");
        let jurisdiction: Option<String> = did_row.get("jurisdiction");
        let created_at: DateTime<Utc> = did_row.get("created_at");

        let method_rows = sqlx::query(
            "SELECT method_id, key_type, public_key, revoked \
             FROM verification_methods WHERE did = $1 ORDER BY method_id",
        )
        .bind(did.as_str())
        .fetch_all(&mut **ctx)
        .await
        .map_err(storage)?;

        let methods = method_rows
            .iter()
            .map(|r| {
                let key_type: String = r.get("key_type");
                let public_key: Vec<u8> = r.get("public_key");
                let bytes: [u8; 32] = public_key
                    .try_into()
                    .map_err(|_| DomainError::Storage("库中公钥摘要长度非法".into()))?;
                Ok(VerificationMethod {
                    id: r.get("method_id"),
                    key_type: enum_from_text(&key_type)
                        .map_err(|e| storage_corrupt("key_type", &key_type, e))?,
                    public_key: Hash32::from_bytes(bytes),
                    controller: parse_did(did_row.get::<&str, _>("id"))?,
                    revoked: r.get("revoked"),
                })
            })
            .collect::<Result<Vec<_>, DomainError>>()?;

        Ok(Some(DidDocument {
            did: parse_did(did_row.get::<&str, _>("id"))?,
            kind: enum_from_text(&kind).map_err(|e| storage_corrupt("kind", &kind, e))?,
            methods,
            parent: parent.as_deref().map(parse_did).transpose()?,
            jurisdiction,
            created_at,
        }))
    }

    /// 写入一条能力委托。
    ///
    /// 幂等语义：同一 `(agent, action)` 重复授予不报错，
    /// 后值覆盖 `granted_by` / `expires_at`（重授予即刷新授权）。
    async fn grant_capability(
        &self,
        ctx: &mut Self::Context,
        cap: &Capability,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO capabilities (agent_did, action, granted_by, expires_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (agent_did, action) DO UPDATE SET \
                 granted_by = EXCLUDED.granted_by, \
                 expires_at = EXCLUDED.expires_at",
        )
        .bind(cap.agent().as_str())
        .bind(enum_to_text(cap.action()))
        .bind(cap.granted_by().as_str())
        .bind(cap.expires_at())
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// 列出某智能体的全部能力（含已过期）；`ORDER BY action` 保证确定性。
    async fn capabilities_of(
        &self,
        ctx: &mut Self::Context,
        agent: &Did,
    ) -> Result<Vec<Capability>, DomainError> {
        let rows = sqlx::query(
            "SELECT agent_did, action, granted_by, expires_at \
             FROM capabilities WHERE agent_did = $1 ORDER BY action",
        )
        .bind(agent.as_str())
        .fetch_all(&mut **ctx)
        .await
        .map_err(storage)?;

        rows.iter()
            .map(|r| {
                let agent_did: &str = r.get("agent_did");
                let action: String = r.get("action");
                let granted_by: &str = r.get("granted_by");
                let expires_at: Option<DateTime<Utc>> = r.get("expires_at");
                Capability::new(
                    parse_did(agent_did)?,
                    enum_from_text(&action).map_err(|e| storage_corrupt("action", &action, e))?,
                    parse_did(granted_by)?,
                    expires_at,
                )
            })
            .collect()
    }
}

/// 还原 [`Action`] 时的损坏数据包装（避免闭包内重复格式化）。
fn storage_corrupt(field: &str, value: &str, err: serde_json::Error) -> DomainError {
    DomainError::Storage(format!("库中 {field} `{value}` 非法：{err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use vg_domain::identity::{Action, KeyType, SubjectKind};

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn enterprise_doc() -> DidDocument {
        let did = Did::parse("did:vg:user:ent-15").unwrap();
        let mut m0 = VerificationMethod::new(
            "k-0",
            KeyType::Secp256k1,
            Hash32::keccak(b"pk0"),
            did.clone(),
        );
        m0.revoked = true;
        let m1 = VerificationMethod::new(
            "k-1",
            KeyType::Secp256k1,
            Hash32::keccak(b"pk1"),
            did.clone(),
        );
        DidDocument {
            did,
            kind: SubjectKind::Enterprise,
            methods: vec![m0, m1],
            parent: None,
            jurisdiction: Some("CN".into()),
            created_at: fixed_time(),
        }
    }

    fn agent_doc() -> DidDocument {
        let did = Did::parse("did:vg:agent:ag-15").unwrap();
        DidDocument {
            did: did.clone(),
            kind: SubjectKind::Agent,
            methods: vec![VerificationMethod::new(
                "a-0",
                KeyType::Secp256k1,
                Hash32::keccak(b"apk"),
                did.clone(),
            )],
            parent: Some(Did::parse("did:vg:user:ent-15").unwrap()),
            jurisdiction: None,
            created_at: fixed_time(),
        }
    }

    /// 保存 → find 深相等往返：多方法（含已撤销）、jurisdiction Some/None、
    /// parent Some/None；未保存的 DID 返回 None。
    #[sqlx::test]
    async fn save_find_roundtrip(pool: sqlx::PgPool) {
        let repo = PgIdentityRepo;
        let mut tx = pool.begin().await.unwrap();

        let ent = enterprise_doc();
        repo.save_document(&mut tx, &ent)
            .await
            .expect("企业文档保存应成功");
        let found = repo
            .find_document(&mut tx, &ent.did)
            .await
            .expect("查询应成功")
            .expect("刚保存的企业文档应能查到");
        // 方法按 method_id 稳定排序（k-0 在前），与原文档构造序一致
        assert_eq!(found, ent);

        let ag = agent_doc();
        repo.save_document(&mut tx, &ag)
            .await
            .expect("智能体文档保存应成功");
        let found = repo
            .find_document(&mut tx, &ag.did)
            .await
            .expect("查询应成功")
            .expect("智能体文档应能查到");
        assert_eq!(found, ag);
        assert_eq!(
            found.jurisdiction, None,
            "jurisdiction None 应原样保留（0002 可空）"
        );

        let missing = repo
            .find_document(&mut tx, &Did::parse("did:vg:user:none-15").unwrap())
            .await
            .expect("查询应成功");
        assert!(missing.is_none());

        tx.commit().await.unwrap();
    }

    /// 二次保存为全量状态同步：撤销旧方法 + 新增方法 + 移除方法都被正确
    /// 落库；created_at 保留首次值（创建时间不可变）。
    #[sqlx::test]
    async fn resave_syncs_full_method_set_and_keeps_created_at(pool: sqlx::PgPool) {
        let repo = PgIdentityRepo;
        let mut tx = pool.begin().await.unwrap();

        let original = enterprise_doc();
        repo.save_document(&mut tx, &original).await.unwrap();

        // 变更：k-1 保留并撤销、新增 k-2、移除 k-0；created_at 换新值
        let mut updated = original.clone();
        updated.methods.retain(|m| m.id != "k-0");
        updated.methods[0].revoked = true;
        let did = updated.did.clone();
        updated.methods.push(VerificationMethod::new(
            "k-2",
            KeyType::Secp256k1,
            Hash32::keccak(b"pk2"),
            did.clone(),
        ));
        let later = fixed_time() + chrono::Duration::days(30);
        updated.created_at = later;

        repo.save_document(&mut tx, &updated).await.unwrap();
        let found = repo
            .find_document(&mut tx, &did)
            .await
            .unwrap()
            .expect("更新后的文档应存在");

        // 方法集 = 第二次保存的完整集合（k-0 被 DELETE 清除）
        let ids: Vec<&str> = found.methods.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["k-1", "k-2"], "方法集应全量同步");
        assert!(
            found.methods.iter().all(|m| m.id != "k-0"),
            "已移除的方法不得残留"
        );
        // created_at 保留首次值
        assert_eq!(
            found.created_at,
            fixed_time(),
            "created_at 应保留首次创建值"
        );
        // 其余字段以第二次保存为准
        assert!(found.methods[0].revoked);
        assert_eq!(found.kind, SubjectKind::Enterprise);

        tx.commit().await.unwrap();
    }

    /// 能力授予幂等：重复授予不报错且覆盖 expires_at/granted_by；
    /// capabilities_of 仅返回本人能力且按 action 有序。
    #[sqlx::test]
    async fn grant_capability_is_idempotent_and_overwrites(pool: sqlx::PgPool) {
        let repo = PgIdentityRepo;
        let mut tx = pool.begin().await.unwrap();

        // capabilities.agent_did 有 FK：先落智能体与其父文档
        let ent = enterprise_doc();
        let ag = agent_doc();
        repo.save_document(&mut tx, &ent).await.unwrap();
        repo.save_document(&mut tx, &ag).await.unwrap();

        let agent = ag.did.clone();
        let grantor = ent.did.clone();
        let later = fixed_time() + chrono::Duration::days(90);

        let first = Capability::new(agent.clone(), Action::CreateBatch, grantor.clone(), None)
            .expect("首次授权应构造成功");
        repo.grant_capability(&mut tx, &first)
            .await
            .expect("首次授予应成功");

        // 第二次：同 (agent, action)，刷新 expires_at —— 幂等不报错
        let second = Capability::new(agent.clone(), Action::CreateBatch, grantor, Some(later))
            .expect("二次授权应构造成功");
        repo.grant_capability(&mut tx, &second)
            .await
            .expect("重复授予应幂等成功");

        // 第三条不同 action，验证多条与排序
        let third =
            Capability::new(agent.clone(), Action::ReadProduct, ent.did.clone(), None).unwrap();
        repo.grant_capability(&mut tx, &third).await.unwrap();

        let caps = repo
            .capabilities_of(&mut tx, &agent)
            .await
            .expect("查询能力应成功");
        assert_eq!(caps.len(), 2, "同 (agent,action) 重复授予只应有 1 条");
        // ORDER BY action：create_batch < read_product
        assert_eq!(caps[0].action(), &Action::CreateBatch);
        assert_eq!(caps[0].expires_at(), Some(later), "重授予应覆盖 expires_at");
        assert_eq!(caps[1].action(), &Action::ReadProduct);

        let other = repo
            .capabilities_of(&mut tx, &Did::parse("did:vg:agent:ag-none").unwrap())
            .await
            .unwrap();
        assert!(other.is_empty());

        tx.commit().await.unwrap();
    }
}
