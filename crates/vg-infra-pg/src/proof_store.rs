//! 证明存档：PostgreSQL 实现（infra 侧服务，Task 19/20 使用）。
//!
//! [`PgProofStore`] 无领域端口（证明落库走 `proofs` 表的存储服务，领域侧
//! 只经 `VerifiedProofRef` 消费结论）：save 幂等 upsert，find 按 proof_id
//! 精确还原。publics 以 FieldElement serde hex 数组落 jsonb。

use vg_domain::ports::FieldElement;
use vg_domain::shared::{DomainError, Hash32};

/// bytea → [`Hash32`]；长度非 32 说明存储层数据损坏。
fn hash32_from_db(bytes: Vec<u8>, field: &str) -> Result<Hash32, DomainError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DomainError::Storage(format!("库中 {field} 长度非法")))?;
    Ok(Hash32::from_bytes(arr))
}

/// 证明落档记录（infra 侧定义，领域侧无对应聚合）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRecord {
    /// 证明标识符。
    pub proof_id: String,
    /// 电路 ID（如 `note_opening`）。
    pub circuit_id: String,
    /// 电路版本（库列 bigint 口径）。
    pub circuit_version: i64,
    /// 电路输入承诺（statement hash，锁定证明对象）。
    pub statement_hash: Hash32,
    /// 原始证明字节（格式由 Prover 实现定义）。
    pub proof: Vec<u8>,
    /// 公共输入（FieldElement serde hex 数组，落 jsonb）。
    pub publics: Vec<FieldElement>,
    /// 是否通过验证。
    pub verified: bool,
}

/// 证明存档的 PostgreSQL 存储（Context 事务模式，与其余仓储同款）。
#[derive(Debug, Default, Clone, Copy)]
pub struct PgProofStore;

impl PgProofStore {
    /// 保存证明记录（按 `proof_id` 幂等 upsert）。
    ///
    /// `ON CONFLICT DO UPDATE` 允许重写 proof 字节与 verified：重证明场景
    /// （同 statement 的新证明产物 / 异步验证结果回填）需覆盖同 id 记录。
    pub async fn save(
        &self,
        ctx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        record: &ProofRecord,
    ) -> Result<(), DomainError> {
        let publics_text = serde_json::to_string(&record.publics)
            .map_err(|e| DomainError::Storage(format!("publics 序列化失败：{e}")))?;
        sqlx::query(
            "INSERT INTO proofs \
                 (proof_id, circuit_id, circuit_version, statement_hash, proof, publics, verified) \
             VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7) \
             ON CONFLICT (proof_id) DO UPDATE SET \
                 circuit_id = EXCLUDED.circuit_id, \
                 circuit_version = EXCLUDED.circuit_version, \
                 statement_hash = EXCLUDED.statement_hash, \
                 proof = EXCLUDED.proof, \
                 publics = EXCLUDED.publics, \
                 verified = EXCLUDED.verified",
        )
        .bind(&record.proof_id)
        .bind(&record.circuit_id)
        .bind(record.circuit_version)
        .bind(record.statement_hash.as_bytes().as_slice())
        .bind(record.proof.as_slice())
        .bind(publics_text)
        .bind(record.verified)
        .execute(&mut **ctx)
        .await
        .map_err(crate::storage)?;
        Ok(())
    }

    /// 按 proof_id 查找；不存在时返回 `Ok(None)`。
    pub async fn find(
        &self,
        ctx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        proof_id: &str,
    ) -> Result<Option<ProofRecord>, DomainError> {
        let row = sqlx::query(
            "SELECT proof_id, circuit_id, circuit_version, statement_hash, proof, \
                    publics::text AS publics, verified \
             FROM proofs WHERE proof_id = $1",
        )
        .bind(proof_id)
        .fetch_optional(&mut **ctx)
        .await
        .map_err(crate::storage)?;

        row.map(|r| {
            use sqlx::Row;
            let statement_hash: Vec<u8> = r.get("statement_hash");
            let proof: Vec<u8> = r.get("proof");
            let publics: String = r.get("publics");
            Ok(ProofRecord {
                proof_id: r.get("proof_id"),
                circuit_id: r.get("circuit_id"),
                circuit_version: r.get("circuit_version"),
                statement_hash: hash32_from_db(statement_hash, "statement_hash")?,
                proof,
                publics: serde_json::from_str(&publics)
                    .map_err(|e| DomainError::Storage(format!("库中 proofs.publics 非法：{e}")))?,
                verified: r.get("verified"),
            })
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// save → find 往返：publics 3 元素 hex、proof 二进制、statement_hash bytea；
    /// 二次 save 重写 verified 与 proof 字节。
    #[sqlx::test]
    async fn save_find_roundtrip_and_rewrite(pool: sqlx::PgPool) {
        let store = PgProofStore;
        let mut tx = pool.begin().await.unwrap();

        let record = ProofRecord {
            proof_id: "pf-17a".into(),
            circuit_id: "note_opening".into(),
            circuit_version: 2,
            statement_hash: Hash32::keccak(b"statement-17"),
            proof: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF],
            publics: vec![
                FieldElement::from_u64(1),
                FieldElement::from_u64(0x0102030405060708),
                FieldElement::from_u64(u64::MAX),
            ],
            verified: false,
        };
        store.save(&mut tx, &record).await.expect("保存应成功");

        let found = store
            .find(&mut tx, "pf-17a")
            .await
            .expect("查询应成功")
            .expect("刚保存的应能查到");
        assert_eq!(found, record, "全字段深相等往返");
        assert_eq!(found.publics.len(), 3);

        assert!(store
            .find(&mut tx, "pf-none")
            .await
            .expect("查询应成功")
            .is_none());

        // 二次 save：重证明场景——proof 字节与 verified 被覆盖
        let mut rewritten = record.clone();
        rewritten.proof = vec![0x01, 0x02, 0x03];
        rewritten.verified = true;
        store.save(&mut tx, &rewritten).await.expect("重写应成功");
        let found = store.find(&mut tx, "pf-17a").await.unwrap().unwrap();
        assert_eq!(found, rewritten);
        assert!(found.verified, "verified 应被重写为 true");

        tx.commit().await.unwrap();
    }
}
