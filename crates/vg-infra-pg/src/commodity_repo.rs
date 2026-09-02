//! 商品仓储：PostgreSQL 实现（Context 事务模式，与 identity/credential 同款）。
//!
//! [`PgCommodityRepo`] 实现 [`CommodityRepository`]，`Context` 绑定为
//! `sqlx::Transaction<'static, Postgres>`——由 application 层开启事务并
//! 经 `&mut` 注入，仓储自身不管理事务生命周期。
//!
//! 谱系唯一事实源是 `batch_lineage` 边表：`batches` 不冗余任何父子列，
//! `lineage_of` / `children_of` / `parents_of` 全部从边表查询。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row;

use vg_domain::commodity::ports::CommodityRepository;
use vg_domain::commodity::{Asset, Batch, LineageEdge, ProductType};
use vg_domain::lifecycle::LifecycleState;
use vg_domain::shared::{AssetId, BatchId, DomainError, Hash32, ProductId};

use crate::{enum_from_text, enum_to_text, parse_did, storage, uint_from_db};

/// 商品上下文的 PostgreSQL 仓储。
#[derive(Debug, Default, Clone, Copy)]
pub struct PgCommodityRepo;

/// bytea → [`Hash32`]；长度非 32 说明存储层数据损坏。
fn hash32_from_db(bytes: Vec<u8>, field: &str) -> Result<Hash32, DomainError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DomainError::Storage(format!("库中 {field} 长度非法")))?;
    Ok(Hash32::from_bytes(arr))
}

#[async_trait]
impl CommodityRepository for PgCommodityRepo {
    type Context = sqlx::Transaction<'static, sqlx::Postgres>;

    /// 保存或整体替换商品类型档案（按 `p.id` 幂等）。
    ///
    /// - `created_at` 保留首次值（`ProductType` 无时间字段，入库以插入时刻
    ///   为准，更新路径不触碰该列——创建时间不可变）；
    /// - category / metadata_hash / active 随整体替换更新。
    async fn save_product(
        &self,
        ctx: &mut Self::Context,
        p: &ProductType,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO products (id, category, metadata_hash, created_at, active) \
             VALUES ($1, $2, $3, now(), $4) \
             ON CONFLICT (id) DO UPDATE SET \
                 category = EXCLUDED.category, \
                 metadata_hash = EXCLUDED.metadata_hash, \
                 active = EXCLUDED.active",
        )
        .bind(p.id.as_ref())
        .bind(&p.category)
        .bind(p.metadata_hash.as_bytes().as_slice())
        .bind(p.active)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// 按商品 ID 查找档案；不存在时返回 `Ok(None)`。
    async fn find_product(
        &self,
        ctx: &mut Self::Context,
        id: &ProductId,
    ) -> Result<Option<ProductType>, DomainError> {
        let row = sqlx::query(
            "SELECT category, metadata_hash, active FROM products WHERE id = $1",
        )
        .bind(id.as_ref())
        .fetch_optional(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(row
            .map(|r| {
                Ok(ProductType {
                    id: id.clone(),
                    category: r.get("category"),
                    metadata_hash: hash32_from_db(r.get("metadata_hash"), "metadata_hash")?,
                    active: r.get("active"),
                })
            })
            .transpose()?)
    }

    /// 保存或整体替换批次（按 `b.id` 幂等）。
    ///
    /// `product_id` 不参与更新：所属商品类型不可变（换产品等于换聚合身份，
    /// 应走新批次）。其余业务字段全部随整体替换。
    async fn save_batch(&self, ctx: &mut Self::Context, b: &Batch) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO batches \
                 (id, product_id, quantity, unit, produced_at, producer, state, \
                  compliance_ok, active) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             ON CONFLICT (id) DO UPDATE SET \
                 quantity = EXCLUDED.quantity, \
                 unit = EXCLUDED.unit, \
                 produced_at = EXCLUDED.produced_at, \
                 producer = EXCLUDED.producer, \
                 state = EXCLUDED.state, \
                 compliance_ok = EXCLUDED.compliance_ok, \
                 active = EXCLUDED.active",
        )
        .bind(b.id.as_ref())
        .bind(b.product.as_ref())
        // u64 数量以 bigint 落库（libsql 口径：数量/计数 bigint）
        .bind(b.quantity as i64)
        .bind(&b.unit)
        .bind(b.produced_at)
        .bind(b.producer.as_str())
        .bind(enum_to_text(&b.state))
        .bind(b.compliance_ok)
        .bind(b.active)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// 按批次 ID 查找；不存在时返回 `Ok(None)`。
    async fn find_batch(
        &self,
        ctx: &mut Self::Context,
        id: &BatchId,
    ) -> Result<Option<Batch>, DomainError> {
        let row = sqlx::query(
            "SELECT product_id, quantity, unit, produced_at, producer, state, \
                    compliance_ok, active \
             FROM batches WHERE id = $1",
        )
        .bind(id.as_ref())
        .fetch_optional(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(row
            .map(|r| {
                Ok(Batch {
                    id: id.clone(),
                    product: ProductId::new(r.get::<String, _>("product_id")),
                    quantity: uint_from_db(r.get("quantity"), "quantity")?,
                    unit: r.get("unit"),
                    produced_at: r.get::<DateTime<Utc>, _>("produced_at"),
                    producer: parse_did(r.get("producer"))?,
                    state: map_state(r.get("state"))?,
                    compliance_ok: r.get("compliance_ok"),
                    active: r.get("active"),
                })
            })
            .transpose()?)
    }

    /// 覆盖式更新批次的生命周期状态与有效标记。
    ///
    /// 迁移合法性由应用层先经 lifecycle 校验，本方法只落库；
    /// 批次不存在（0 行命中）→ [`DomainError::NotFound`]。
    async fn update_batch_state(
        &self,
        ctx: &mut Self::Context,
        id: &BatchId,
        state: LifecycleState,
        active: bool,
    ) -> Result<(), DomainError> {
        let result = sqlx::query("UPDATE batches SET state = $2, active = $3 WHERE id = $1")
            .bind(id.as_ref())
            .bind(enum_to_text(&state))
            .bind(active)
            .execute(&mut **ctx)
            .await
            .map_err(storage)?;
        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound);
        }
        Ok(())
    }

    /// Task 22 合规重算结论回写：仅更新 `compliance_ok`；
    /// 批次不存在（0 行命中）→ [`DomainError::NotFound`]。
    async fn update_batch_compliance(
        &self,
        ctx: &mut Self::Context,
        id: &BatchId,
        compliance_ok: bool,
    ) -> Result<(), DomainError> {
        let result = sqlx::query("UPDATE batches SET compliance_ok = $2 WHERE id = $1")
            .bind(id.as_ref())
            .bind(compliance_ok)
            .execute(&mut **ctx)
            .await
            .map_err(storage)?;
        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound);
        }
        Ok(())
    }

    /// 保存或整体替换单品资产（按 `a.id` 幂等，含 transfer_count/c2c_count）。
    async fn save_asset(&self, ctx: &mut Self::Context, a: &Asset) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO assets \
                 (id, product_id, manufacturer, authenticity_commitment, created_at, \
                  state, transfer_count, c2c_count) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT (id) DO UPDATE SET \
                 manufacturer = EXCLUDED.manufacturer, \
                 authenticity_commitment = EXCLUDED.authenticity_commitment, \
                 state = EXCLUDED.state, \
                 transfer_count = EXCLUDED.transfer_count, \
                 c2c_count = EXCLUDED.c2c_count",
        )
        .bind(a.id.as_ref())
        .bind(a.product.as_ref())
        .bind(a.manufacturer.as_str())
        .bind(a.authenticity_commitment.as_bytes().as_slice())
        .bind(a.created_at)
        .bind(enum_to_text(&a.state))
        .bind(a.transfer_count as i64)
        .bind(a.c2c_count as i64)
        .execute(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// 按单品 ID 查找；不存在时返回 `Ok(None)`。
    async fn find_asset(
        &self,
        ctx: &mut Self::Context,
        id: &AssetId,
    ) -> Result<Option<Asset>, DomainError> {
        let row = sqlx::query(
            "SELECT product_id, manufacturer, authenticity_commitment, created_at, \
                    state, transfer_count, c2c_count \
             FROM assets WHERE id = $1",
        )
        .bind(id.as_ref())
        .fetch_optional(&mut **ctx)
        .await
        .map_err(storage)?;
        Ok(row
            .map(|r| {
                Ok(Asset {
                    id: id.clone(),
                    product: ProductId::new(r.get::<String, _>("product_id")),
                    manufacturer: parse_did(r.get("manufacturer"))?,
                    authenticity_commitment: hash32_from_db(
                        r.get("authenticity_commitment"),
                        "authenticity_commitment",
                    )?,
                    created_at: r.get("created_at"),
                    state: map_state(r.get("state"))?,
                    transfer_count: uint_from_db(r.get("transfer_count"), "transfer_count")?,
                    c2c_count: uint_from_db(r.get("c2c_count"), "c2c_count")?,
                })
            })
            .transpose()?)
    }

    /// 追加一批谱系边：`ON CONFLICT (parent, child) DO NOTHING`。
    ///
    /// 边不可变：同一父子关系重复落库不报错也不改写（幂等），
    /// 与内存参考实现的 `(parent, child, op)` 去重语义一致
    /// （PK 即 (parent, child)，op 冲突由先落者胜出）。
    async fn save_lineage(
        &self,
        ctx: &mut Self::Context,
        edges: &[LineageEdge],
    ) -> Result<(), DomainError> {
        for edge in edges {
            sqlx::query(
                "INSERT INTO batch_lineage (parent, child, op, at) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (parent, child) DO NOTHING",
            )
            .bind(edge.parent.as_ref())
            .bind(edge.child.as_ref())
            .bind(enum_to_text(&edge.op))
            .bind(edge.at)
            .execute(&mut **ctx)
            .await
            .map_err(storage)?;
        }
        Ok(())
    }

    /// 与某批次相关的全部谱系边（出边 + 入边），`ORDER BY parent, child`
    /// 确定性返回（边表无追加序，以键序稳定输出）。
    async fn lineage_of(
        &self,
        ctx: &mut Self::Context,
        id: &BatchId,
    ) -> Result<Vec<LineageEdge>, DomainError> {
        let rows = sqlx::query(
            "SELECT parent, child, op, at FROM batch_lineage \
             WHERE parent = $1 OR child = $1 ORDER BY parent, child",
        )
        .bind(id.as_ref())
        .fetch_all(&mut **ctx)
        .await
        .map_err(storage)?;
        rows.iter().map(map_edge).collect()
    }

    /// 某批次作为 parent 的全部子批 ID，`ORDER BY child` 确定性返回。
    async fn children_of(
        &self,
        ctx: &mut Self::Context,
        id: &BatchId,
    ) -> Result<Vec<BatchId>, DomainError> {
        let rows = sqlx::query("SELECT child FROM batch_lineage WHERE parent = $1 ORDER BY child")
            .bind(id.as_ref())
            .fetch_all(&mut **ctx)
            .await
            .map_err(storage)?;
        Ok(rows
            .iter()
            .map(|r| BatchId::new(r.get::<String, _>("child")))
            .collect())
    }

    /// 某批次作为 child 的全部父批 ID，`ORDER BY parent` 确定性返回。
    async fn parents_of(
        &self,
        ctx: &mut Self::Context,
        id: &BatchId,
    ) -> Result<Vec<BatchId>, DomainError> {
        let rows = sqlx::query("SELECT parent FROM batch_lineage WHERE child = $1 ORDER BY parent")
            .bind(id.as_ref())
            .fetch_all(&mut **ctx)
            .await
            .map_err(storage)?;
        Ok(rows
            .iter()
            .map(|r| BatchId::new(r.get::<String, _>("parent")))
            .collect())
    }
}

/// 库中文本 → [`LifecycleState`] 的损坏数据包装。
fn map_state(text: String) -> Result<LifecycleState, DomainError> {
    enum_from_text(&text)
        .map_err(|e| DomainError::Storage(format!("库中生命周期状态 `{text}` 非法：{e}")))
}

/// 行 → [`LineageEdge`]。
fn map_edge(r: &sqlx::postgres::PgRow) -> Result<LineageEdge, DomainError> {
    let op: String = r.get("op");
    Ok(LineageEdge {
        parent: BatchId::new(r.get::<String, _>("parent")),
        child: BatchId::new(r.get::<String, _>("child")),
        op: enum_from_text(&op)
            .map_err(|e| DomainError::Storage(format!("库中谱系 op `{op}` 非法：{e}")))?,
        at: r.get("at"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use vg_domain::commodity::LineageOp;
    use vg_domain::shared::Did;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 0, 0, 0).unwrap()
    }

    fn later_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 26, 8, 30, 0).unwrap()
    }

    fn producer() -> Did {
        Did::parse("did:vg:user:factory-16").unwrap()
    }

    fn sample_product(id: &str) -> ProductType {
        ProductType::new(ProductId::new(id), "milk", Hash32::keccak(b"meta-16"))
            .expect("样例商品应构造成功")
    }

    fn sample_batch(id: &str, quantity: u64) -> Batch {
        Batch::new(
            BatchId::new(id),
            ProductId::new("p-16"),
            quantity,
            "box",
            fixed_time(),
            producer(),
        )
        .expect("样例批次应构造成功")
    }

    /// 商品类型：save → find 往返；整体替换（category/hash/active）生效；
    /// 未保存返回 None。
    #[sqlx::test]
    async fn product_upsert_and_roundtrip(pool: sqlx::PgPool) {
        let repo = PgCommodityRepo;
        let mut tx = pool.begin().await.unwrap();

        let p = sample_product("p-16");
        repo.save_product(&mut tx, &p).await.expect("保存商品应成功");
        assert_eq!(
            repo.find_product(&mut tx, &p.id).await.unwrap(),
            Some(p.clone()),
            "首次保存后应原样回读"
        );

        // 整体替换：下架 + 换类目/哈希
        let mut updated = p.clone();
        updated.active = false;
        updated.category = "cold_chain".into();
        updated.metadata_hash = Hash32::keccak(b"meta-16-v2");
        repo.save_product(&mut tx, &updated).await.unwrap();
        assert_eq!(repo.find_product(&mut tx, &p.id).await.unwrap(), Some(updated));

        assert!(
            repo.find_product(&mut tx, &ProductId::new("p-none"))
                .await
                .unwrap()
                .is_none()
        );

        tx.commit().await.unwrap();
    }

    /// 计划重点场景：一个事务内落 split——父批 active=false + 两个子批 +
    /// 两条谱系边；commit 后回读父/子状态、边与父辈边重建全部正确。
    #[sqlx::test]
    async fn split_persists_children_edges_and_parent_inactive_in_one_tx(pool: sqlx::PgPool) {
        let repo = PgCommodityRepo;
        let mut tx = pool.begin().await.unwrap();

        repo.save_product(&mut tx, &sample_product("p-16"))
            .await
            .unwrap();

        // 预置"父之父"边素材：祖父批 → 父批（验证谱系重建不依赖 batches 列）
        let grandparent = sample_batch("b-gp", 20);
        repo.save_batch(&mut tx, &grandparent).await.unwrap();

        let parent = sample_batch("b-parent", 10);
        repo.save_batch(&mut tx, &parent).await.unwrap();
        repo.save_lineage(
            &mut tx,
            &[LineageEdge {
                parent: grandparent.id.clone(),
                child: parent.id.clone(),
                op: LineageOp::Split,
                at: fixed_time(),
            }],
        )
        .await
        .unwrap();

        // 拆分：同一 ctx 内写父（active=false）、两子批、两边
        let mut parent = parent;
        let outcome = parent
            .split(
                &[(BatchId::new("b-left"), 6), (BatchId::new("b-right"), 4)],
                later_time(),
            )
            .expect("拆分应成功");
        repo.save_batch(&mut tx, &parent).await.unwrap();
        for child in &outcome.children {
            repo.save_batch(&mut tx, child).await.unwrap();
        }
        repo.save_lineage(&mut tx, &outcome.edges).await.unwrap();

        tx.commit().await.unwrap();

        // commit 后在新事务回读：父批 active=false 且状态不变（仍是 created）
        let mut tx = pool.begin().await.unwrap();
        let stored_parent = repo
            .find_batch(&mut tx, &BatchId::new("b-parent"))
            .await
            .unwrap()
            .expect("父批应存在");
        assert!(!stored_parent.active, "拆分后父批必须失效");
        assert_eq!(stored_parent.state, LifecycleState::Created);
        assert_eq!(stored_parent.quantity, 10, "父批数量保留原值供追溯");

        let left = repo
            .find_batch(&mut tx, &BatchId::new("b-left"))
            .await
            .unwrap()
            .expect("左子批应存在");
        assert_eq!((left.quantity, left.active), (6, true));

        // 边查询：children_of / parents_of / lineage_of
        let kids = repo
            .children_of(&mut tx, &BatchId::new("b-parent"))
            .await
            .unwrap();
        assert_eq!(kids, vec![BatchId::new("b-left"), BatchId::new("b-right")]);

        let folks = repo
            .parents_of(&mut tx, &BatchId::new("b-left"))
            .await
            .unwrap();
        assert_eq!(folks, vec![BatchId::new("b-parent")]);

        // 父批 lineage_of：1 入边（祖父）+ 2 出边（两子）= 3 条
        let edges = repo
            .lineage_of(&mut tx, &BatchId::new("b-parent"))
            .await
            .unwrap();
        assert_eq!(edges.len(), 3, "父批应有 1 入边 + 2 出边");
        // 0004 起 at 列落库，边可无损往返
        assert!(edges.iter().any(|e| e.parent == grandparent.id
            && e.child == parent.id
            && e.op == LineageOp::Split
            && e.at == fixed_time()));
        assert!(edges
            .iter()
            .filter(|e| e.child == BatchId::new("b-left"))
            .all(|e| e.at == later_time()));

        // save_lineage 幂等：同边二次保存不报错、不产生新记录
        repo.save_lineage(&mut tx, &outcome.edges)
            .await
            .expect("重复保存谱系应幂等成功");
        assert_eq!(
            repo.children_of(&mut tx, &BatchId::new("b-parent"))
                .await
                .unwrap()
                .len(),
            2,
            "重复保存不得新增边"
        );

        tx.commit().await.unwrap();
    }

    /// update_batch_state：状态+有效标记覆盖式落库；不存在 → NotFound。
    #[sqlx::test]
    async fn update_batch_state_covers_state_and_active(pool: sqlx::PgPool) {
        let repo = PgCommodityRepo;
        let mut tx = pool.begin().await.unwrap();

        repo.save_product(&mut tx, &sample_product("p-16"))
            .await
            .unwrap();
        let batch = sample_batch("b-state", 5);
        repo.save_batch(&mut tx, &batch).await.unwrap();

        repo.update_batch_state(
            &mut tx,
            &batch.id,
            LifecycleState::Produced,
            batch.active,
        )
        .await
        .expect("状态更新应成功");
        let stored = repo.find_batch(&mut tx, &batch.id).await.unwrap().unwrap();
        assert_eq!(stored.state, LifecycleState::Produced);
        assert!(stored.active);

        // 再覆盖：Recalled + 失效
        repo.update_batch_state(&mut tx, &batch.id, LifecycleState::Recalled, false)
            .await
            .unwrap();
        let stored = repo.find_batch(&mut tx, &batch.id).await.unwrap().unwrap();
        assert_eq!(stored.state, LifecycleState::Recalled);
        assert!(!stored.active);

        // 不存在 → NotFound
        let err = repo
            .update_batch_state(
                &mut tx,
                &BatchId::new("b-nope"),
                LifecycleState::Produced,
                true,
            )
            .await
            .expect_err("不存在的批次必须报 NotFound");
        assert!(matches!(err, DomainError::NotFound), "{err:?}");

        tx.commit().await.unwrap();
    }

    /// update_batch_compliance：compliance_ok 回写；不存在 → NotFound。
    #[sqlx::test]
    async fn update_batch_compliance_persists_flag(pool: sqlx::PgPool) {
        let repo = PgCommodityRepo;
        let mut tx = pool.begin().await.unwrap();

        repo.save_product(&mut tx, &sample_product("p-16"))
            .await
            .unwrap();
        let batch = sample_batch("b-cmp", 5);
        repo.save_batch(&mut tx, &batch).await.unwrap();

        repo.update_batch_compliance(&mut tx, &batch.id, true)
            .await
            .expect("合规回写应成功");
        assert!(
            repo.find_batch(&mut tx, &batch.id).await.unwrap().unwrap().compliance_ok
        );
        repo.update_batch_compliance(&mut tx, &batch.id, false)
            .await
            .unwrap();
        assert!(
            !repo.find_batch(&mut tx, &batch.id).await.unwrap().unwrap().compliance_ok
        );

        let err = repo
            .update_batch_compliance(&mut tx, &BatchId::new("b-nope"), true)
            .await
            .expect_err("不存在的批次必须报 NotFound");
        assert!(matches!(err, DomainError::NotFound), "{err:?}");

        tx.commit().await.unwrap();
    }

    /// 单品：save → find 往返 + transfer_count/c2c_count 持久化
    /// （save 后改计数再 save 再 find，新值必须落库）。
    #[sqlx::test]
    async fn asset_roundtrip_and_counters_persist(pool: sqlx::PgPool) {
        let repo = PgCommodityRepo;
        let mut tx = pool.begin().await.unwrap();

        repo.save_product(&mut tx, &sample_product("p-16"))
            .await
            .unwrap();
        let asset = Asset::new(
            AssetId::new("a-16"),
            ProductId::new("p-16"),
            producer(),
            Hash32::keccak(b"commit-16"),
            fixed_time(),
        )
        .unwrap();
        repo.save_asset(&mut tx, &asset).await.unwrap();
        assert_eq!(repo.find_asset(&mut tx, &asset.id).await.unwrap(), Some(asset.clone()));

        // 模拟所有权上下文回填计数：改计数再 save 再 find
        let mut updated = asset;
        updated.transfer_count = 3;
        updated.c2c_count = 2;
        updated.state = LifecycleState::Sold;
        repo.save_asset(&mut tx, &updated).await.unwrap();
        let stored = repo
            .find_asset(&mut tx, &updated.id)
            .await
            .unwrap()
            .expect("单品应存在");
        assert_eq!((stored.transfer_count, stored.c2c_count), (3, 2));
        assert_eq!(stored.state, LifecycleState::Sold);

        assert!(
            repo.find_asset(&mut tx, &AssetId::new("a-none"))
                .await
                .unwrap()
                .is_none()
        );

        tx.commit().await.unwrap();
    }
}
