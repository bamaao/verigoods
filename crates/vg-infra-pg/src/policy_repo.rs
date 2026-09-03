//! 策略仓储：PostgreSQL 实现（Context 事务模式，与 identity/commodity 同款）。
//!
//! [`PgPolicyRepository`] 实现 [`PolicyRepository`]：
//! - 监管域 `regulatory_domains`（`product_types` / `credential_schemas`
//!   以 jsonb 文本绑定，照 credential claims 先例）；
//! - 策略 `policies`，PK `(policy_id, version)` 支撑版本化引用；
//!   `required` 列结构约定为 `{"credentials":[...],"proofs":[...]}`
//!   （值均为 serde snake_case，见 0001 迁移注释）。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;

use vg_domain::credential::CredentialType;
use vg_domain::lifecycle::LifecycleState;
use vg_domain::policy::ports::PolicyRepository;
use vg_domain::policy::{Policy, ProofKind, RegulatoryDomain};
use vg_domain::shared::{DomainError, PolicyId};

use crate::{parse_did, storage, uint_from_db};

/// 策略与监管域上下文的 PostgreSQL 仓储。
#[derive(Debug, Default, Clone, Copy)]
pub struct PgPolicyRepository;

/// jsonb 文本绑定前的序列化包装（错误归为 Storage，与 claims 先例一致）。
fn jsonb_text<T: serde::Serialize>(value: &T, field: &str) -> Result<String, DomainError> {
    serde_json::to_string(value)
        .map_err(|e| DomainError::Storage(format!("{field} 序列化失败：{e}")))
}

/// `required` 列的领域编码：`{"credentials":[...],"proofs":[...]}`。
///
/// 值经 serde 序列化取 snake_case 字符串，与 CHECK 白名单口径永不漂移
/// （与 [`enum_to_text`] 同一原则）。
fn encode_required(
    credentials: &[CredentialType],
    proofs: &[ProofKind],
) -> Result<String, DomainError> {
    let value = serde_json::json!({
        "credentials": serde_json::to_value(credentials)
            .map_err(|e| DomainError::Storage(format!("required.credentials 序列化失败：{e}")))?,
        "proofs": serde_json::to_value(proofs)
            .map_err(|e| DomainError::Storage(format!("required.proofs 序列化失败：{e}")))?,
    });
    Ok(value.to_string())
}

/// `required` 列 → 领域字段；结构不符说明存储层数据损坏，报 Storage 错误。
fn decode_required(
    raw: &str,
    id: &PolicyId,
) -> Result<(Vec<CredentialType>, Vec<ProofKind>), DomainError> {
    let corrupt = |detail: String| {
        DomainError::Storage(format!("库中策略 {id} 的 required 列非法：{detail}"))
    };
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| corrupt(format!("非合法 JSON：{e}")))?;
    let credentials: Vec<CredentialType> = serde_json::from_value(
        value
            .get("credentials")
            .cloned()
            .ok_or_else(|| corrupt("缺少 credentials 键".into()))?,
    )
    .map_err(|e| corrupt(format!("credentials 反序列化失败：{e}")))?;
    let proofs: Vec<ProofKind> = serde_json::from_value(
        value
            .get("proofs")
            .cloned()
            .ok_or_else(|| corrupt("缺少 proofs 键".into()))?,
    )
    .map_err(|e| corrupt(format!("proofs 反序列化失败：{e}")))?;
    Ok((credentials, proofs))
}

/// `transitions` 列 → 领域字段；serde 元组数组天然往返（`[["created","produced"],...]`）。
fn decode_transitions(
    raw: &str,
    id: &PolicyId,
) -> Result<Vec<(LifecycleState, LifecycleState)>, DomainError> {
    serde_json::from_str(raw)
        .map_err(|e| DomainError::Storage(format!("库中策略 {id} 的 transitions 列非法：{e}")))
}

#[async_trait]
impl PolicyRepository for PgPolicyRepository {
    type Context = sqlx::Transaction<'static, sqlx::Postgres>;

    /// 保存监管域（按 `domain_id` 幂等 upsert，全列更新）。
    ///
    /// `product_types` / `credential_schemas` 以 serde 序列化文本 +
    /// `::jsonb` cast 绑定（sqlx 未启用 json feature，照 Task 15 claims 先例）。
    async fn save_domain(
        &self,
        ctx: &mut Self::Context,
        domain: &RegulatoryDomain,
    ) -> Result<(), DomainError> {
        let product_types = jsonb_text(&domain.product_types, "product_types")?;
        let credential_schemas = jsonb_text(&domain.credential_schemas, "credential_schemas")?;
        sqlx::query(
            "INSERT INTO regulatory_domains \
                 (domain_id, authority, jurisdiction, product_types, credential_schemas, effective_from) \
             VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6) \
             ON CONFLICT (domain_id) DO UPDATE SET \
                 authority = EXCLUDED.authority, \
                 jurisdiction = EXCLUDED.jurisdiction, \
                 product_types = EXCLUDED.product_types, \
                 credential_schemas = EXCLUDED.credential_schemas, \
                 effective_from = EXCLUDED.effective_from",
        )
        .bind(&domain.domain_id)
        .bind(domain.authority.as_str())
        .bind(&domain.jurisdiction)
        .bind(product_types)
        .bind(credential_schemas)
        .bind(domain.effective_from)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// 按域 ID 查找；不存在时返回 `Ok(None)`。jsonb 列损坏报 Storage 错误。
    async fn find_domain(
        &self,
        ctx: &mut Self::Context,
        domain_id: &str,
    ) -> Result<Option<RegulatoryDomain>, DomainError> {
        let row = sqlx::query(
            "SELECT domain_id, authority, jurisdiction, \
                    product_types::text AS product_types, \
                    credential_schemas::text AS credential_schemas, effective_from \
             FROM regulatory_domains WHERE domain_id = $1",
        )
        .bind(domain_id)
        .fetch_optional(&mut **ctx)
        .await
        .map_err(storage)?;

        Ok(row
            .map(|r| {
                let product_types: String = r.get("product_types");
                let credential_schemas: String = r.get("credential_schemas");
                Ok(RegulatoryDomain {
                    domain_id: r.get("domain_id"),
                    authority: parse_did(r.get("authority"))?,
                    jurisdiction: r.get("jurisdiction"),
                    product_types: serde_json::from_str(&product_types).map_err(|e| {
                        DomainError::Storage(format!(
                            "库中监管域 {domain_id} 的 product_types 非法：{e}"
                        ))
                    })?,
                    credential_schemas: serde_json::from_str(&credential_schemas).map_err(|e| {
                        DomainError::Storage(format!(
                            "库中监管域 {domain_id} 的 credential_schemas 非法：{e}"
                        ))
                    })?,
                    effective_from: r.get("effective_from"),
                })
            })
            .transpose()?)
    }

    /// 保存策略（按 `(policy_id, version)` 幂等 upsert，全列更新）。
    ///
    /// `required` / `transitions` 为 jsonb 文本绑定；u64 version 以 bigint 落库。
    async fn save_policy(
        &self,
        ctx: &mut Self::Context,
        policy: &Policy,
    ) -> Result<(), DomainError> {
        let required = encode_required(&policy.required_credentials, &policy.required_proofs)?;
        let transitions = jsonb_text(&policy.transitions, "transitions")?;
        sqlx::query(
            "INSERT INTO policies \
                 (policy_id, version, authority, jurisdiction, product_type, required, \
                  transitions, effective_at, expires_at, active) \
             VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, $10) \
             ON CONFLICT (policy_id, version) DO UPDATE SET \
                 authority = EXCLUDED.authority, \
                 jurisdiction = EXCLUDED.jurisdiction, \
                 product_type = EXCLUDED.product_type, \
                 required = EXCLUDED.required, \
                 transitions = EXCLUDED.transitions, \
                 effective_at = EXCLUDED.effective_at, \
                 expires_at = EXCLUDED.expires_at, \
                 active = EXCLUDED.active",
        )
        .bind(policy.policy_id.as_ref())
        .bind(policy.version as i64)
        .bind(policy.authority.as_str())
        .bind(&policy.jurisdiction)
        .bind(&policy.product_type)
        .bind(required)
        .bind(transitions)
        .bind(policy.effective_at)
        .bind(policy.expires_at)
        .bind(policy.active)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// 按 `(policy_id, version)` 精确查找；不存在时返回 `Ok(None)`。
    async fn find_policy(
        &self,
        ctx: &mut Self::Context,
        id: &PolicyId,
        version: u64,
    ) -> Result<Option<Policy>, DomainError> {
        let row = sqlx::query(
            "SELECT policy_id, version, authority, jurisdiction, product_type, \
                    required::text AS required, transitions::text AS transitions, \
                    effective_at, expires_at, active \
             FROM policies WHERE policy_id = $1 AND version = $2",
        )
        .bind(id.as_ref())
        .bind(version as i64)
        .fetch_optional(&mut **ctx)
        .await
        .map_err(storage)?;

        Ok(row
            .map(|r| {
                let authority: String = r.get("authority");
                let required: String = r.get("required");
                let transitions: String = r.get("transitions");
                let (required_credentials, required_proofs) = decode_required(&required, id)?;
                Ok(Policy {
                    policy_id: PolicyId::new(r.get::<String, _>("policy_id")),
                    version: uint_from_db(r.get("version"), "policy version")?,
                    authority: parse_did(&authority)?,
                    jurisdiction: r.get("jurisdiction"),
                    product_type: r.get("product_type"),
                    required_credentials,
                    required_proofs,
                    transitions: decode_transitions(&transitions, id)?,
                    effective_at: r.get::<DateTime<Utc>, _>("effective_at"),
                    expires_at: r.get("expires_at"),
                    active: r.get("active"),
                })
            })
            .transpose()?)
    }

    /// 按辖区 + 商品类型取候选策略。
    ///
    /// **含 inactive**：`is_active(now)` 过滤留给调用方——引擎按业务时刻
    /// 判定，仓储不做时间假设（领域端口契约）。
    ///
    /// `ORDER BY policy_id, version`（审查既定，与 identity 的
    /// active_pubkey ORDER BY 教训同源）：调用方（策略引擎 / 审计）按顺序
    /// 消费 enforced 版本序列，必须保证确定性输出序。
    async fn policies_for(
        &self,
        ctx: &mut Self::Context,
        jurisdiction: &str,
        product_type: &str,
    ) -> Result<Vec<Policy>, DomainError> {
        let rows = sqlx::query(
            "SELECT policy_id, version, authority, jurisdiction, product_type, \
                    required::text AS required, transitions::text AS transitions, \
                    effective_at, expires_at, active \
             FROM policies \
             WHERE jurisdiction = $1 AND product_type = $2 \
             ORDER BY policy_id, version",
        )
        .bind(jurisdiction)
        .bind(product_type)
        .fetch_all(&mut **ctx)
        .await
        .map_err(storage)?;

        rows.iter()
            .map(|r| {
                let policy_id: String = r.get("policy_id");
                let id = PolicyId::new(&policy_id);
                let authority: String = r.get("authority");
                let required: String = r.get("required");
                let transitions: String = r.get("transitions");
                let (required_credentials, required_proofs) = decode_required(&required, &id)?;
                Ok(Policy {
                    version: uint_from_db(r.get("version"), "policy version")?,
                    authority: parse_did(&authority)?,
                    jurisdiction: r.get("jurisdiction"),
                    product_type: r.get("product_type"),
                    required_credentials,
                    required_proofs,
                    transitions: decode_transitions(&transitions, &id)?,
                    effective_at: r.get::<DateTime<Utc>, _>("effective_at"),
                    expires_at: r.get("expires_at"),
                    active: r.get("active"),
                    policy_id: id,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use sqlx::Row;
    use vg_domain::credential::CredentialSchema;
    use vg_domain::shared::Did;

    fn t(month: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, month, 1, 0, 0, 0).unwrap()
    }

    fn sample_domain() -> RegulatoryDomain {
        RegulatoryDomain {
            domain_id: "vg:domain:cn-food-17".into(),
            authority: Did::parse("did:vg:user:reg-17").unwrap(),
            jurisdiction: "CN".into(),
            product_types: vec!["food".into(), "beverage".into()],
            credential_schemas: vec![
                CredentialSchema {
                    id: "vg:schema:food-safety@v1".into(),
                    ctype: CredentialType::FoodSafetyInspection,
                    required_claims: vec!["result".into()],
                },
                CredentialSchema {
                    id: "vg:schema:customs@v1".into(),
                    ctype: CredentialType::Customs,
                    required_claims: vec!["port".into(), "declared_at".into()],
                },
            ],
            effective_from: t(1),
        }
    }

    fn sample_policy(id: &str, version: u64, jurisdiction: &str, product_type: &str) -> Policy {
        Policy {
            policy_id: PolicyId::new(id),
            version,
            authority: Did::parse("did:vg:user:reg-17").unwrap(),
            jurisdiction: jurisdiction.into(),
            product_type: product_type.into(),
            required_credentials: vec![CredentialType::Customs, CredentialType::Tax],
            required_proofs: vec![ProofKind::ColdChain, ProofKind::Ownership],
            transitions: vec![
                (LifecycleState::Created, LifecycleState::Produced),
                (LifecycleState::InWarehouse, LifecycleState::InTransit),
            ],
            effective_at: t(1),
            expires_at: Some(t(12)),
            active: true,
        }
    }

    /// 监管域往返：product_types 数组 + credential_schemas（含多 schema）深相等。
    #[sqlx::test]
    async fn domain_roundtrip(pool: sqlx::PgPool) {
        let repo = PgPolicyRepository;
        let mut tx = pool.begin().await.unwrap();

        let domain = sample_domain();
        repo.save_domain(&mut tx, &domain)
            .await
            .expect("保存应成功");
        let found = repo
            .find_domain(&mut tx, "vg:domain:cn-food-17")
            .await
            .expect("查询应成功")
            .expect("刚保存的域应能查到");
        assert_eq!(found, domain, "监管域往返应深相等（含 2 个 schema）");

        // 未保存的域 → None
        assert!(repo
            .find_domain(&mut tx, "vg:domain:none")
            .await
            .expect("查询应成功")
            .is_none());

        // 二次保存（upsert）覆盖 jurisdiction
        let mut updated = domain.clone();
        updated.jurisdiction = "EU".into();
        repo.save_domain(&mut tx, &updated)
            .await
            .expect("重存应成功");
        assert_eq!(
            repo.find_domain(&mut tx, "vg:domain:cn-food-17")
                .await
                .unwrap()
                .unwrap()
                .jurisdiction,
            "EU"
        );

        tx.commit().await.unwrap();
    }

    /// 策略往返：同 id 双版本共存、find 各自命中、required/transitions
    /// jsonb 深相等（transitions 含 2 条边）；(id,version) upsert 覆盖。
    #[sqlx::test]
    async fn policy_two_versions_coexist_and_roundtrip(pool: sqlx::PgPool) {
        let repo = PgPolicyRepository;
        let mut tx = pool.begin().await.unwrap();

        let v1 = sample_policy("pol-17x", 1, "CN", "food");
        let mut v2 = sample_policy("pol-17x", 2, "CN", "food");
        v2.required_proofs = vec![ProofKind::Range];
        repo.save_policy(&mut tx, &v1).await.expect("v1 保存应成功");
        repo.save_policy(&mut tx, &v2).await.expect("v2 保存应成功");

        let found1 = repo
            .find_policy(&mut tx, &PolicyId::new("pol-17x"), 1)
            .await
            .expect("查询应成功")
            .expect("v1 应存在");
        let found2 = repo
            .find_policy(&mut tx, &PolicyId::new("pol-17x"), 2)
            .await
            .expect("查询应成功")
            .expect("v2 应存在");
        assert_eq!(found1, v1, "v1 深相等往返（required/transitions jsonb）");
        assert_eq!(found2, v2, "v2 深相等往返，required_proofs 独立不串版本");

        // jsonb 列结构抽查：required 为 {"credentials":[...],"proofs":[...]}
        // （jsonb 的 ::text 输出为键序无关的规范形，故按解析后的值断言）
        let raw: String = sqlx::query(
            "SELECT required::text FROM policies WHERE policy_id = 'pol-17x' AND version = 1",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap()
        .get(0);
        let required_value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            required_value,
            serde_json::json!({
                "credentials": ["customs", "tax"],
                "proofs": ["cold_chain", "ownership"]
            }),
            "required 列应严格符合 0001 结构约定"
        );

        // 未命中版本 → None
        assert!(repo
            .find_policy(&mut tx, &PolicyId::new("pol-17x"), 3)
            .await
            .expect("查询应成功")
            .is_none());

        // upsert：同 (id,version) 重存覆盖 active
        let mut v2b = v2.clone();
        v2b.active = false;
        repo.save_policy(&mut tx, &v2b).await.expect("重存应成功");
        assert!(
            !repo
                .find_policy(&mut tx, &PolicyId::new("pol-17x"), 2)
                .await
                .unwrap()
                .unwrap()
                .active
        );

        tx.commit().await.unwrap();
    }

    /// policies_for：辖区/商品类型全等过滤（异辖区、异商品类型排除），
    /// **含 inactive**，且严格按 (policy_id, version) 有序——乱序插入
    /// 多 id 多版本验证确定性输出序（审查既定）。
    #[sqlx::test]
    async fn policies_for_filters_includes_inactive_and_orders(pool: sqlx::PgPool) {
        let repo = PgPolicyRepository;
        let mut tx = pool.begin().await.unwrap();

        // 乱序插入：b-v2、a-v2、b-v1、a-v1 + 异辖区/异类型干扰项
        let b2 = sample_policy("pol-17b", 2, "CN", "food");
        let a2 = sample_policy("pol-17a", 2, "CN", "food");
        let b1 = sample_policy("pol-17b", 1, "CN", "food");
        let mut a1 = sample_policy("pol-17a", 1, "CN", "food");
        a1.active = false; // inactive 也必须返回（时间/开关过滤归调用方）
        let eu = sample_policy("pol-17eu", 1, "EU", "food");
        let electronics = sample_policy("pol-17e", 1, "CN", "electronics");
        for p in [&b2, &a2, &b1, &a1, &eu, &electronics] {
            repo.save_policy(&mut tx, p).await.expect("保存应成功");
        }

        let got = repo
            .policies_for(&mut tx, "CN", "food")
            .await
            .expect("查询应成功");
        let keys: Vec<(String, u64)> = got
            .iter()
            .map(|p| (p.policy_id.to_string(), p.version))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("pol-17a".to_string(), 1),
                ("pol-17a".to_string(), 2),
                ("pol-17b".to_string(), 1),
                ("pol-17b".to_string(), 2),
            ],
            "应按 (policy_id, version) 严格有序，且含 inactive 的 a-v1"
        );
        assert!(got
            .iter()
            .all(|p| p.jurisdiction == "CN" && p.product_type == "food"));
        // inactive 项确实在列
        assert!(got.iter().any(|p| !p.active));

        // 无匹配 → 空
        assert!(repo
            .policies_for(&mut tx, "US", "food")
            .await
            .expect("查询应成功")
            .is_empty());

        tx.commit().await.unwrap();
    }
}
