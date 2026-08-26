//! 商品上下文：商品类型、批次、单品与谱系。
//!
//! - [`product`]：商品类型（类目 + 元数据哈希承诺）；
//! - [`batch`]：批次聚合（拆分/合并的数量守恒规则与谱系产出）；
//! - [`asset`]：单品资产（防伪承诺与转移计数）；
//! - [`lineage`]：谱系边（拆分/合并/加工的父子关系事实）；
//! - [`ports`]：持久化与上链锚定端口（由基础设施层实现，领域层只定义契约）。

pub mod asset;
pub mod batch;
pub mod lineage;
pub mod product;

pub use asset::Asset;
pub use batch::{Batch, MergeOutcome, SplitOutcome};
pub use lineage::{LineageEdge, LineageOp};
pub use product::ProductType;

/// 商品上下文的端口集合。
pub mod ports {
    use async_trait::async_trait;

    use crate::lifecycle::LifecycleState;
    use crate::shared::{AssetId, BatchId, DomainError, ProductId};

    use super::{Asset, Batch, LineageEdge, ProductType};

    /// 商品上下文的持久化端口。
    ///
    /// 实现方为具体存储适配器（如 PostgreSQL，Task 16）；领域层与测试用内存实现。
    #[async_trait]
    pub trait CommodityRepository {
        /// 事务/会话上下文类型，由实现方定义。
        ///
        /// 必须为 `Send`：axum handler 要求 future 为 `Send`，
        /// 跨 `.await` 持有 ctx 时该关联类型约束是前提
        /// （与 identity / credential / lifecycle 同一约定）。
        type Context: Send;

        /// 保存或整体替换商品类型档案（按 `p.id` 幂等）。
        async fn save_product(
            &self,
            ctx: &mut Self::Context,
            p: &ProductType,
        ) -> Result<(), DomainError>;

        /// 按商品 ID 查找档案；不存在时返回 `Ok(None)`。
        async fn find_product(
            &self,
            ctx: &mut Self::Context,
            id: &ProductId,
        ) -> Result<Option<ProductType>, DomainError>;

        /// 保存或整体替换批次（按 `b.id` 幂等）。
        async fn save_batch(&self, ctx: &mut Self::Context, b: &Batch) -> Result<(), DomainError>;

        /// 按批次 ID 查找；不存在时返回 `Ok(None)`。
        async fn find_batch(
            &self,
            ctx: &mut Self::Context,
            id: &BatchId,
        ) -> Result<Option<Batch>, DomainError>;

        /// 覆盖式更新批次的生命周期状态与有效标记。
        ///
        /// 状态迁移合法性由应用层先经 lifecycle 的 `assert_transition`
        /// 校验，本方法只负责落库；批次不存在 → [`DomainError::NotFound`]。
        async fn update_batch_state(
            &self,
            ctx: &mut Self::Context,
            id: &BatchId,
            state: LifecycleState,
            active: bool,
        ) -> Result<(), DomainError>;

        /// 保存或整体替换单品资产（按 `a.id` 幂等）。
        async fn save_asset(&self, ctx: &mut Self::Context, a: &Asset) -> Result<(), DomainError>;

        /// 按单品 ID 查找；不存在时返回 `Ok(None)`。
        async fn find_asset(
            &self,
            ctx: &mut Self::Context,
            id: &AssetId,
        ) -> Result<Option<Asset>, DomainError>;

        /// 追加一批谱系边（实现方可按 `(parent, child, op)` 幂等去重）。
        async fn save_lineage(
            &self,
            ctx: &mut Self::Context,
            edges: &[LineageEdge],
        ) -> Result<(), DomainError>;

        /// 返回与某批次**相关的全部谱系边**：既含该批作为 `parent` 的出边，
        /// 也含该批作为 `child` 的入边（按追加序返回，不区分方向）。
        async fn lineage_of(
            &self,
            ctx: &mut Self::Context,
            id: &BatchId,
        ) -> Result<Vec<LineageEdge>, DomainError>;

        /// 某批次作为 `parent` 的全部子批 ID（按边追加序，可重复出现）。
        async fn children_of(
            &self,
            ctx: &mut Self::Context,
            id: &BatchId,
        ) -> Result<Vec<BatchId>, DomainError>;

        /// 某批次作为 `child` 的全部父批 ID（按边追加序，可重复出现）。
        async fn parents_of(
            &self,
            ctx: &mut Self::Context,
            id: &BatchId,
        ) -> Result<Vec<BatchId>, DomainError>;
    }

    /// 商品创建上链锚定端口（infra 实现：InProcessLedger / alloy，Task 18/26）。
    ///
    /// 将批次建档/拆分/合并与单品建档以事件形式写入账本，
    /// 供链下/链上核验方对账。
    #[async_trait]
    pub trait CommodityAnchorPort: Send + Sync {
        /// 锚定"批次建档"事件。
        async fn anchor_batch_created(&self, b: &Batch) -> Result<(), DomainError>;

        /// 锚定"批次拆分"事件：父批与全部子批 ID 上链。
        async fn anchor_batch_split(
            &self,
            parent: &BatchId,
            children: &[BatchId],
        ) -> Result<(), DomainError>;

        /// 锚定"批次合并"事件：全部父批与新批 ID 上链。
        async fn anchor_batch_merged(
            &self,
            parents: &[BatchId],
            child: &BatchId,
        ) -> Result<(), DomainError>;

        /// 锚定"单品建档"事件。
        async fn anchor_asset_created(&self, a: &Asset) -> Result<(), DomainError>;
    }
}

#[cfg(test)]
mod tests {
    use super::ports::{CommodityAnchorPort, CommodityRepository};
    use super::*;
    use crate::lifecycle::LifecycleState;
    use crate::shared::{AssetId, BatchId, Did, DomainError, Hash32, ProductId};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::collections::HashMap;
    use std::future::Future;

    // ---- 内存仓储：锁定端口形状，并作为存储适配器的参考实现 ----

    #[derive(Default)]
    struct MemStore {
        products: HashMap<ProductId, ProductType>,
        batches: HashMap<BatchId, Batch>,
        assets: HashMap<AssetId, Asset>,
        edges: Vec<LineageEdge>,
    }

    struct MemRepo;

    #[async_trait]
    impl CommodityRepository for MemRepo {
        type Context = MemStore;

        async fn save_product(
            &self,
            ctx: &mut Self::Context,
            p: &ProductType,
        ) -> Result<(), DomainError> {
            ctx.products.insert(p.id.clone(), p.clone());
            Ok(())
        }

        async fn find_product(
            &self,
            ctx: &mut Self::Context,
            id: &ProductId,
        ) -> Result<Option<ProductType>, DomainError> {
            Ok(ctx.products.get(id).cloned())
        }

        async fn save_batch(&self, ctx: &mut Self::Context, b: &Batch) -> Result<(), DomainError> {
            ctx.batches.insert(b.id.clone(), b.clone());
            Ok(())
        }

        async fn find_batch(
            &self,
            ctx: &mut Self::Context,
            id: &BatchId,
        ) -> Result<Option<Batch>, DomainError> {
            Ok(ctx.batches.get(id).cloned())
        }

        async fn update_batch_state(
            &self,
            ctx: &mut Self::Context,
            id: &BatchId,
            state: LifecycleState,
            active: bool,
        ) -> Result<(), DomainError> {
            let b = ctx.batches.get_mut(id).ok_or(DomainError::NotFound)?;
            b.state = state;
            b.active = active;
            Ok(())
        }

        async fn save_asset(&self, ctx: &mut Self::Context, a: &Asset) -> Result<(), DomainError> {
            ctx.assets.insert(a.id.clone(), a.clone());
            Ok(())
        }

        async fn find_asset(
            &self,
            ctx: &mut Self::Context,
            id: &AssetId,
        ) -> Result<Option<Asset>, DomainError> {
            Ok(ctx.assets.get(id).cloned())
        }

        async fn save_lineage(
            &self,
            ctx: &mut Self::Context,
            edges: &[LineageEdge],
        ) -> Result<(), DomainError> {
            for edge in edges {
                // 按 (parent, child, op) 幂等：同一关系不重复落库
                if !ctx
                    .edges
                    .iter()
                    .any(|e| e.parent == edge.parent && e.child == edge.child && e.op == edge.op)
                {
                    ctx.edges.push(edge.clone());
                }
            }
            Ok(())
        }

        async fn lineage_of(
            &self,
            ctx: &mut Self::Context,
            id: &BatchId,
        ) -> Result<Vec<LineageEdge>, DomainError> {
            // 双向查询：作为 parent 的出边 + 作为 child 的入边
            Ok(ctx
                .edges
                .iter()
                .filter(|e| &e.parent == id || &e.child == id)
                .cloned()
                .collect())
        }

        async fn children_of(
            &self,
            ctx: &mut Self::Context,
            id: &BatchId,
        ) -> Result<Vec<BatchId>, DomainError> {
            Ok(ctx
                .edges
                .iter()
                .filter(|e| &e.parent == id)
                .map(|e| e.child.clone())
                .collect())
        }

        async fn parents_of(
            &self,
            ctx: &mut Self::Context,
            id: &BatchId,
        ) -> Result<Vec<BatchId>, DomainError> {
            Ok(ctx
                .edges
                .iter()
                .filter(|e| &e.child == id)
                .map(|e| e.parent.clone())
                .collect())
        }
    }

    /// 内存锚定 fake：记录调用序列供断言；字段须 Send+Sync 以满足端口约束。
    #[derive(Default)]
    struct MemAnchor {
        log: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl CommodityAnchorPort for MemAnchor {
        async fn anchor_batch_created(&self, b: &Batch) -> Result<(), DomainError> {
            self.log
                .lock()
                .unwrap()
                .push(format!("batch-created:{}:{}{}", b.id, b.quantity, b.unit));
            Ok(())
        }

        async fn anchor_batch_split(
            &self,
            parent: &BatchId,
            children: &[BatchId],
        ) -> Result<(), DomainError> {
            let names = children
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(",");
            self.log
                .lock()
                .unwrap()
                .push(format!("batch-split:{parent}:({names})"));
            Ok(())
        }

        async fn anchor_batch_merged(
            &self,
            parents: &[BatchId],
            child: &BatchId,
        ) -> Result<(), DomainError> {
            let names = parents
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            self.log
                .lock()
                .unwrap()
                .push(format!("batch-merged:({names}):{child}"));
            Ok(())
        }

        async fn anchor_asset_created(&self, a: &Asset) -> Result<(), DomainError> {
            self.log.lock().unwrap().push(format!(
                "asset-created:{}:{}",
                a.id, a.authenticity_commitment
            ));
            Ok(())
        }
    }

    /// 极简 block_on（与 credential / lifecycle 同款）：内存 fake 的 future
    /// 永远就绪，noop waker 即足够；领域层禁止引入 tokio 等运行时依赖，
    /// 测试自带最小驱动器。
    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        loop {
            if let std::task::Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
            // 内存实现不会真正 Pending；若意外 Pending 则自旋重试。
        }
    }

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 0, 0, 0).unwrap()
    }

    fn producer() -> Did {
        Did::parse("did:vg:user:factory-1").unwrap()
    }

    fn sample_product() -> ProductType {
        ProductType::new(ProductId::new("p-milk"), "milk", Hash32::keccak(b"meta"))
            .expect("样例商品应构造成功")
    }

    fn sample_batch(id: &str, quantity: u64) -> Batch {
        Batch::new(
            BatchId::new(id),
            ProductId::new("p-milk"),
            quantity,
            "box",
            fixed_time(),
            producer(),
        )
        .expect("样例批次应构造成功")
    }

    #[test]
    fn commodity_repository_roundtrips_batches_assets_and_lineage() {
        let repo = MemRepo;
        let mut ctx = MemStore::default();

        // ---- 商品：save → find 回读一致；未保存返回 None ----
        let product = sample_product();
        let pid = product.id.clone();
        block_on(repo.save_product(&mut ctx, &product)).expect("保存商品应成功");
        let found = block_on(repo.find_product(&mut ctx, &pid)).expect("查询不应报错");
        assert_eq!(found, Some(product));
        assert!(
            block_on(repo.find_product(&mut ctx, &ProductId::new("nope")))
                .unwrap()
                .is_none()
        );

        // ---- 批次：建档、拆分、保存父子与谱系 ----
        let parent = sample_batch("b-root", 10);
        let parent_id = parent.id.clone();
        block_on(repo.save_batch(&mut ctx, &parent)).expect("保存父批应成功");

        let mut parent = parent;
        let outcome = parent
            .split(
                &[(BatchId::new("b-l"), 6), (BatchId::new("b-r"), 4)],
                fixed_time(),
            )
            .expect("拆分应成功");
        for child in &outcome.children {
            block_on(repo.save_batch(&mut ctx, child)).expect("保存子批应成功");
        }
        block_on(repo.save_lineage(&mut ctx, &outcome.edges)).expect("保存谱系应成功");
        // 父批失效经覆盖式更新落库
        block_on(repo.update_batch_state(&mut ctx, &parent_id, parent.state, parent.active))
            .expect("更新父批应成功");

        // save/find 回读：父批已失效、子批可查、缺失返回 None
        let stored_parent = block_on(repo.find_batch(&mut ctx, &parent_id))
            .unwrap()
            .expect("父批应存在");
        assert!(!stored_parent.active);
        let stored_child = block_on(repo.find_batch(&mut ctx, &BatchId::new("b-l")))
            .unwrap()
            .expect("子批应存在");
        assert_eq!(stored_child.quantity, 6);
        assert!(block_on(repo.find_batch(&mut ctx, &BatchId::new("nope")))
            .unwrap()
            .is_none());

        // update_batch_state：ID 不存在 → NotFound
        let err = block_on(repo.update_batch_state(
            &mut ctx,
            &BatchId::new("nope"),
            LifecycleState::Produced,
            true,
        ))
        .expect_err("不存在的批次必须报 NotFound");
        assert!(matches!(err, DomainError::NotFound));

        // ---- 单品：save/find 回读一致 ----
        let asset = Asset::new(
            AssetId::new("a-1"),
            ProductId::new("p-milk"),
            producer(),
            Hash32::keccak(b"commit"),
            fixed_time(),
        )
        .expect("样例单品应构造成功");
        let aid = asset.id.clone();
        block_on(repo.save_asset(&mut ctx, &asset)).expect("保存单品应成功");
        let found = block_on(repo.find_asset(&mut ctx, &aid))
            .unwrap()
            .expect("单品应存在");
        assert_eq!(found, asset);
        assert!(block_on(repo.find_asset(&mut ctx, &AssetId::new("nope")))
            .unwrap()
            .is_none());

        // ---- 谱系：lineage_of 双向查询 ----
        // 父批：两条出边（作为 parent）
        let from_parent = block_on(repo.lineage_of(&mut ctx, &parent_id)).expect("查询不应报错");
        assert_eq!(from_parent.len(), 2, "父批应有 2 条出边");
        assert!(from_parent.iter().all(|e| e.parent == parent_id));

        // 子批：一条入边（作为 child）
        let left_id = BatchId::new("b-l");
        let of_child = block_on(repo.lineage_of(&mut ctx, &left_id)).expect("查询不应报错");
        assert_eq!(of_child.len(), 1, "子批应有 1 条入边");
        assert_eq!(of_child[0].child, left_id);
        assert_eq!(of_child[0].parent, parent_id);

        // 无关批次：无边
        assert!(
            block_on(repo.lineage_of(&mut ctx, &BatchId::new("unrelated")))
                .unwrap()
                .is_empty()
        );

        // children_of / parents_of
        let kids = block_on(repo.children_of(&mut ctx, &parent_id)).expect("查询不应报错");
        assert_eq!(kids.len(), 2);
        assert!(kids.contains(&BatchId::new("b-l")));
        assert!(kids.contains(&BatchId::new("b-r")));
        let folks = block_on(repo.parents_of(&mut ctx, &left_id)).expect("查询不应报错");
        assert_eq!(folks, vec![parent_id.clone()]);

        // save_lineage 幂等：重复保存同一关系不产生新记录
        block_on(repo.save_lineage(&mut ctx, &outcome.edges)).expect("重复保存应幂等成功");
        assert_eq!(
            block_on(repo.lineage_of(&mut ctx, &parent_id))
                .unwrap()
                .len(),
            2,
            "重复保存不得新增记录"
        );
    }

    #[test]
    fn commodity_anchor_port_records_events() {
        let anchor = MemAnchor::default();
        let batch = sample_batch("b-anchor", 7);
        let asset = Asset::new(
            AssetId::new("a-9"),
            ProductId::new("p-milk"),
            producer(),
            Hash32::keccak(b"c9"),
            fixed_time(),
        )
        .expect("样例单品应构造成功");

        block_on(anchor.anchor_batch_created(&batch)).expect("锚定建档应成功");
        block_on(anchor.anchor_batch_split(
            &BatchId::new("b-anchor"),
            &[BatchId::new("b-x"), BatchId::new("b-y")],
        ))
        .expect("锚定拆分应成功");
        block_on(anchor.anchor_batch_merged(
            &[BatchId::new("b-x"), BatchId::new("b-y")],
            &BatchId::new("b-z"),
        ))
        .expect("锚定合并应成功");
        block_on(anchor.anchor_asset_created(&asset)).expect("锚定单品应成功");

        let log = anchor.log.lock().unwrap().join("\n");
        assert!(
            log.contains("batch-created:b-anchor:7box"),
            "实际日志：{log}"
        );
        assert!(
            log.contains("batch-split:b-anchor:(b-x,b-y)"),
            "实际日志：{log}"
        );
        assert!(
            log.contains("batch-merged:(b-x,b-y):b-z"),
            "实际日志：{log}"
        );
        assert!(log.contains("asset-created:a-9:"), "实际日志：{log}");
    }

    /// 编译期哨兵（与 identity / credential / lifecycle 同款）：
    /// `R::Context: Send` 必须由端口声明本身提供。
    fn requires_context_send<R: CommodityRepository>(ctx: R::Context) {
        fn needs_send<T: Send>(_: T) {}
        needs_send(ctx);
    }

    #[test]
    fn port_context_must_be_send() {
        requires_context_send::<MemRepo>(MemStore::default());
    }
}
