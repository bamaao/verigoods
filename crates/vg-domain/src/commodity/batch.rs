//! 批次聚合：生产建档、拆分与合并的数量守恒规则。
//!
//! [`Batch`] 是商品流通的聚合根：一次生产产出记为一个批次，后续可
//! **拆分**（一个父批 → 多个子批）或**合并**（多个同源父批 → 一个新批），
//! 两种操作都要求**数量守恒**，并产出 [`LineageEdge`](super::lineage::LineageEdge)
//! 谱系边供追溯。

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::lifecycle::LifecycleState;
use crate::shared::{BatchId, Did, DomainError, ProductId};

use super::lineage::{LineageEdge, LineageOp};

/// 批次（Batch）：同一次生产产出的一组商品的聚合根。
///
/// 不变式：
/// - `quantity > 0`、`unit` 非空；
/// - `active = false` 表示该批次已因拆分/合并而失效（档案保留供追溯，
///   但不可再参与新的流通操作）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    /// 批次标识符。
    pub id: BatchId,
    /// 所属商品类型。
    pub product: ProductId,
    /// 数量（以 `unit` 计）。
    pub quantity: u64,
    /// 计量单位（如 `"kg"`、`"box"`），非空。
    pub unit: String,
    /// 生产时刻。
    pub produced_at: DateTime<Utc>,
    /// 生产者 DID。
    pub producer: Did,
    /// 生命周期状态（13 态状态机，初始为 Created）。
    pub state: LifecycleState,
    /// 合规结论（由应用层合规重算回填，建档时默认 `false`）。
    pub compliance_ok: bool,
    /// 是否有效（拆分/合并后父批置为 `false`）。
    pub active: bool,
}

/// [`Batch::split`] 的返回：子批次集合与应记录的谱系边（每对父子一条）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitOutcome {
    /// 新产生的子批次。
    pub children: Vec<Batch>,
    /// 应持久化的谱系边，`op` 均为 [`LineageOp::Split`]。
    pub edges: Vec<LineageEdge>,
}

/// [`Batch::merge`] 的返回：新批次与应记录的谱系边（每对父子一条）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeOutcome {
    /// 合并产生的新批次。
    pub batch: Batch,
    /// 应持久化的谱系边，`op` 均为 [`LineageOp::Merge`]。
    pub edges: Vec<LineageEdge>,
}

impl Batch {
    /// 创建批次档案。
    ///
    /// 规则：`quantity` 必须 > 0、`unit` 非空（否则
    /// [`DomainError::InvalidInput`]）；状态初始为
    /// [`LifecycleState::Created`]，`active = true`。
    pub fn new(
        id: BatchId,
        product: ProductId,
        quantity: u64,
        unit: impl Into<String>,
        produced_at: DateTime<Utc>,
        producer: Did,
    ) -> Result<Self, DomainError> {
        if quantity == 0 {
            return Err(DomainError::InvalidInput("批次数量必须大于 0".into()));
        }
        let unit = unit.into();
        if unit.is_empty() {
            return Err(DomainError::InvalidInput("计量单位不能为空".into()));
        }
        Ok(Self {
            id,
            product,
            quantity,
            unit,
            produced_at,
            producer,
            state: LifecycleState::Created,
            // 合规结论由应用层（合规重算）回填，建档时默认不合规
            compliance_ok: false,
            active: true,
        })
    }

    /// 拆分当前批次为多个子批次。
    ///
    /// 入参 `children` 为 `(子批 ID, 数量)` 列表；`at` 为本次拆分的记账时刻，
    /// 由调用方（应用层）注入并填入谱系边——领域层不读取真实时钟。
    ///
    /// 规则：
    /// - 只允许在**有效且非终态**的批次上拆分：已失效（`active = false`，
    ///   如已被拆分/合并的父批）或已进入终态 →
    ///   [`DomainError::InvalidTransition`]。失效守卫防止对同一份存量
    ///   重复拆出等量子批（数量双花）；
    /// - 至少一个子批次；每个子批数量 > 0、ID 不等于父批 ID 且互不相同
    ///   （违反 → [`DomainError::InvalidInput`]）；
    /// - 子批数量之和必须等于父批数量（含求和溢出，否则
    ///   [`DomainError::QuantityMismatch`]）。
    ///
    /// 成功后：子批继承 `product` / `unit` / `produced_at` / `compliance_ok`
    /// 与父批的 `producer`，状态为 [`LifecycleState::Created`] 且有效；
    /// 父批置为失效（`active = false`）。同时返回每对父子一条的
    /// [`LineageOp::Split`] 谱系边（时间戳取 `at`）。
    pub fn split(
        &mut self,
        children: &[(BatchId, u64)],
        at: DateTime<Utc>,
    ) -> Result<SplitOutcome, DomainError> {
        // 前置条件一：批次必须仍然有效——已被拆分/合并的父批不可再拆分（防双花）
        if !self.active {
            return Err(DomainError::InvalidTransition {
                from: format!("{}({})，已失效", self.state.zh_name(), self.state),
                to: "拆分(split)".into(),
            });
        }
        // 前置条件二：聚合自身必须处于非终态
        if self.state.is_terminal() {
            return Err(DomainError::InvalidTransition {
                from: format!("{}({})", self.state.zh_name(), self.state),
                to: "拆分(split)".into(),
            });
        }
        // 入参结构校验
        if children.is_empty() {
            return Err(DomainError::InvalidInput("拆分至少需要一个子批次".into()));
        }
        let mut seen = HashSet::with_capacity(children.len());
        for (child_id, quantity) in children {
            if *quantity == 0 {
                return Err(DomainError::InvalidInput(format!(
                    "子批次 {child_id} 数量必须大于 0"
                )));
            }
            if *child_id == self.id {
                return Err(DomainError::InvalidInput(format!(
                    "子批次 ID 不能与父批次相同：{child_id}"
                )));
            }
            if !seen.insert(child_id) {
                return Err(DomainError::InvalidInput(format!(
                    "子批次 ID 重复：{child_id}"
                )));
            }
        }
        // 数量守恒（checked 溢出必然超过父批数量，同样按不一致处理）
        let total = children
            .iter()
            .try_fold(0u64, |acc, (_, q)| acc.checked_add(*q))
            .ok_or(DomainError::QuantityMismatch)?;
        if total != self.quantity {
            return Err(DomainError::QuantityMismatch);
        }

        // 子批继承父批字段；边集合与子批一一对应，时间戳统一取注入的 `at`
        let child_batches = children
            .iter()
            .map(|(child_id, quantity)| Batch {
                id: child_id.clone(),
                product: self.product.clone(),
                quantity: *quantity,
                unit: self.unit.clone(),
                produced_at: self.produced_at,
                producer: self.producer.clone(),
                state: LifecycleState::Created,
                compliance_ok: self.compliance_ok,
                active: true,
            })
            .collect::<Vec<_>>();
        let edges = child_batches
            .iter()
            .map(|child| LineageEdge {
                parent: self.id.clone(),
                child: child.id.clone(),
                op: LineageOp::Split,
                at,
            })
            .collect();
        // 数量已全部转移到子批，父批失效
        self.active = false;
        Ok(SplitOutcome {
            children: child_batches,
            edges,
        })
    }

    /// 将多个同源父批次合并为一个新批次（关联函数）。
    ///
    /// 入参 `at` 为本次合并的记账时刻，由调用方（应用层）注入并填入
    /// 谱系边——领域层不读取真实时钟。
    ///
    /// 规则（任一违规即报错，原因为中文说明）：
    /// - 至少一个父批次（[`DomainError::InvalidInput`]）；
    /// - 全部父批必须 `product` / `unit` / `producer` 一致且均有效
    ///   （`active`）、均非终态——一致性/有效性违规 →
    ///   [`DomainError::InvalidInput`]，终态违规 →
    ///   [`DomainError::InvalidTransition`]；
    /// - 新批数量 = 各父批数量之和（含求和溢出 →
    ///   [`DomainError::InvalidInput`]）；**不变量**：新批 `produced_at`
    ///   恒取各父批最早生产时间 `min(children.produced_at)`；
    /// - 合规继承采用保守策略：仅当全部父批合规时新批才合规；
    /// - 成功后新批状态 [`LifecycleState::Created`] 且有效；各父批置为失效。
    ///
    /// 返回新批次与每对父子一条的 [`LineageOp::Merge`] 谱系边
    /// （时间戳取 `at`）。
    pub fn merge(
        children: &mut [Batch],
        new_id: BatchId,
        producer: Did,
        at: DateTime<Utc>,
    ) -> Result<MergeOutcome, DomainError> {
        if children.is_empty() {
            return Err(DomainError::InvalidInput("合并至少需要一个父批次".into()));
        }
        // 同源校验：以第一个父批为基准，逐个核对一致性、有效性与终态
        let head = &children[0];
        for batch in children.iter() {
            if batch.product != head.product {
                return Err(DomainError::InvalidInput(format!(
                    "父批次 {} 商品类型不一致：期望 {}，实际 {}",
                    batch.id, head.product, batch.product
                )));
            }
            if batch.unit != head.unit {
                return Err(DomainError::InvalidInput(format!(
                    "父批次 {} 计量单位不一致：期望 {}，实际 {}",
                    batch.id, head.unit, batch.unit
                )));
            }
            if batch.producer != head.producer {
                return Err(DomainError::InvalidInput(format!(
                    "父批次 {} 生产者不一致：期望 {}，实际 {}",
                    batch.id, head.producer, batch.producer
                )));
            }
            if !batch.active {
                return Err(DomainError::InvalidInput(format!(
                    "父批次 {} 已失效（active=false），不可参与合并",
                    batch.id
                )));
            }
            if batch.state.is_terminal() {
                return Err(DomainError::InvalidTransition {
                    from: format!("{}({})", batch.state.zh_name(), batch.state),
                    to: format!("合并(merge) → {new_id}"),
                });
            }
        }

        // 总量守恒；溢出属输入异常（u64 无法承载合并结果）
        let quantity = children
            .iter()
            .try_fold(0u64, |acc, b| acc.checked_add(b.quantity))
            .ok_or_else(|| DomainError::InvalidInput("合并后的总数量溢出 u64".into()))?;
        // 不变量：新批 produced_at 恒取各父批最早生产时间
        let produced_at = children
            .iter()
            .map(|b| b.produced_at)
            .min()
            .expect("已在上方保证至少一个父批次");

        // 谱系边每父批一条，时间戳统一取注入的 `at`
        let edges = children
            .iter()
            .map(|p| LineageEdge {
                parent: p.id.clone(),
                child: new_id.clone(),
                op: LineageOp::Merge,
                at,
            })
            .collect();
        // 合规继承采用保守策略：全部父批合规才视为合规
        let batch = Batch {
            id: new_id,
            product: head.product.clone(),
            quantity,
            unit: head.unit.clone(),
            produced_at,
            // 各父批生产者已校验一致；新批生产者由调用方指定（通常与之相同）
            producer,
            state: LifecycleState::Created,
            compliance_ok: children.iter().all(|b| b.compliance_ok),
            active: true,
        };
        for p in children.iter_mut() {
            p.active = false;
        }
        Ok(MergeOutcome { batch, edges })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 0, 0, 0).unwrap()
    }

    fn earlier_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 20, 8, 30, 0).unwrap()
    }

    fn producer() -> Did {
        Did::parse("did:vg:user:factory-1").unwrap()
    }

    fn make_batch(id: &str, quantity: u64) -> Batch {
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

    // ---- 1. 构造校验 ----

    #[test]
    fn new_rejects_zero_quantity_and_empty_unit() {
        let err = Batch::new(
            BatchId::new("b-1"),
            ProductId::new("p-1"),
            0,
            "box",
            fixed_time(),
            producer(),
        )
        .expect_err("数量为 0 必须被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)), "{err:?}");

        let err = Batch::new(
            BatchId::new("b-2"),
            ProductId::new("p-1"),
            5,
            "",
            fixed_time(),
            producer(),
        )
        .expect_err("空单位必须被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)), "{err:?}");
    }

    #[test]
    fn new_starts_created_and_active() {
        let b = make_batch("b-3", 10);
        assert_eq!(b.state, LifecycleState::Created, "初始状态应为 Created");
        assert!(b.active, "新建批次应有效");
        assert_eq!(b.quantity, 10);
        assert_eq!(b.unit, "box");
        assert_eq!(b.producer, producer());
        assert!(!b.compliance_ok, "建档时合规结论默认为 false");
    }

    // ---- 2. 拆分正常路径 ----

    #[test]
    fn split_two_children_conserves_quantity_and_inherits_fields() {
        let mut parent = make_batch("b-p", 10);
        parent.compliance_ok = true;

        let outcome = parent
            .split(
                &[(BatchId::new("b-c1"), 6), (BatchId::new("b-c2"), 4)],
                fixed_time(),
            )
            .expect("守恒拆分应成功");

        // 数量守恒 + 字段继承
        assert_eq!(outcome.children.len(), 2);
        let (c1, c2) = (&outcome.children[0], &outcome.children[1]);
        assert_eq!((c1.quantity, c2.quantity), (6, 4));
        assert_eq!(c1.quantity + c2.quantity, 10, "子批总量必须等于父批");
        for child in [&outcome.children[0], &outcome.children[1]] {
            assert_eq!(child.product, ProductId::new("p-milk"), "应继承商品类型");
            assert_eq!(child.unit, "box", "应继承计量单位");
            assert_eq!(child.produced_at, fixed_time(), "应继承生产时间");
            assert_eq!(child.producer, producer(), "生产者同父批");
            assert!(child.compliance_ok, "应继承合规结论");
            assert_eq!(child.state, LifecycleState::Created, "子批初始 Created");
            assert!(child.active, "子批初始有效");
        }

        // 父批失效
        assert!(!parent.active, "拆分后父批应置为失效");

        // 谱系边：每子批一条，op=Split，方向 parent→child，时间戳取注入时钟
        assert_eq!(outcome.edges.len(), 2);
        for (edge, child) in outcome.edges.iter().zip(outcome.children.iter()) {
            assert_eq!(edge.parent, BatchId::new("b-p"));
            assert_eq!(edge.child, child.id);
            assert_eq!(edge.op, LineageOp::Split);
            assert_eq!(edge.at, fixed_time(), "谱系边时间戳应使用注入时钟");
        }
    }

    // ---- 3. 拆分异常路径 ----

    #[test]
    fn split_quantity_mismatch_is_rejected() {
        let mut parent = make_batch("b-p2", 10);
        let err = parent
            .split(
                &[(BatchId::new("x"), 6), (BatchId::new("y"), 5)],
                fixed_time(),
            )
            .expect_err("11 != 10 必须报数量不一致");
        assert!(matches!(err, DomainError::QuantityMismatch), "{err:?}");
        // 失败不得产生副作用
        assert!(parent.active, "失败的拆分不应改变父批状态");
    }

    #[test]
    fn split_empty_children_list_is_invalid_input() {
        let mut parent = make_batch("b-p3", 10);
        let err = parent
            .split(&[], fixed_time())
            .expect_err("至少需要一个子批次");
        assert!(matches!(err, DomainError::InvalidInput(_)), "{err:?}");
    }

    #[test]
    fn split_duplicate_child_ids_are_invalid_input() {
        let mut parent = make_batch("b-p4", 10);
        let err = parent
            .split(
                &[(BatchId::new("dup"), 5), (BatchId::new("dup"), 5)],
                fixed_time(),
            )
            .expect_err("重复子批 ID 必须被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)), "{err:?}");
    }

    #[test]
    fn split_child_id_equal_to_parent_is_invalid_input() {
        let mut parent = make_batch("b-p5", 10);
        let err = parent
            .split(&[(BatchId::new("b-p5"), 10)], fixed_time())
            .expect_err("子批 ID 等于父批 ID 必须被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)), "{err:?}");
    }

    #[test]
    fn split_zero_quantity_child_is_invalid_input() {
        let mut parent = make_batch("b-p6", 10);
        let err = parent
            .split(
                &[(BatchId::new("a"), 0), (BatchId::new("b"), 10)],
                fixed_time(),
            )
            .expect_err("子批数量为 0 必须被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)), "{err:?}");
    }

    #[test]
    fn split_terminal_parent_is_invalid_transition() {
        let mut parent = make_batch("b-p7", 10);
        parent.state = LifecycleState::Destroyed;
        let err = parent
            .split(&[(BatchId::new("c"), 10)], fixed_time())
            .expect_err("终态批次不允许拆分");
        assert!(
            matches!(err, DomainError::InvalidTransition { .. }),
            "{err:?}"
        );
    }

    // ---- 3.5 失效守卫：防数量双花 ----

    #[test]
    fn split_on_already_split_parent_is_invalid_transition() {
        let mut parent = make_batch("dp-1", 10);
        let first = parent
            .split(
                &[(BatchId::new("d-c1"), 6), (BatchId::new("d-c2"), 4)],
                fixed_time(),
            )
            .expect("首次拆分应成功");
        assert_eq!(first.children.len(), 2);
        assert!(!parent.active, "首次拆分后父批应失效");

        // 已拆分过的父批（active=false 但非终态）不可再次拆分，
        // 否则将凭空再造一份等量子批，造成数量双花
        let err = parent
            .split(&[(BatchId::new("d-x"), 10)], fixed_time())
            .expect_err("失效父批不允许再次拆分");
        assert!(
            matches!(err, DomainError::InvalidTransition { .. }),
            "实际错误：{err:?}"
        );
    }

    #[test]
    fn batch_deactivated_by_merge_cannot_be_split_again() {
        // 合并把全部父批置为 active=false；这些旧父批同样不可再作为拆分源
        let mut parents = vec![make_batch("mg-1", 4), make_batch("mg-2", 6)];
        Batch::merge(
            &mut parents,
            BatchId::new("mg-new"),
            producer(),
            fixed_time(),
        )
        .expect("同源合并应成功");
        assert!(parents.iter().all(|b| !b.active), "合并后旧父批都应失效");

        let mut stale = parents.remove(0); // 模拟从仓储读出的失效旧批
        let err = stale
            .split(&[(BatchId::new("mg-z"), 4)], fixed_time())
            .expect_err("合并后失效的旧父批不允许再拆分");
        assert!(
            matches!(err, DomainError::InvalidTransition { .. }),
            "实际错误：{err:?}"
        );
    }

    // ---- 4. 合并正常路径 ----

    #[test]
    fn merge_three_same_origin_batches_sums_quantity_and_takes_earliest_time() {
        let mut batches = vec![
            make_batch("m-1", 3),
            make_batch("m-2", 5),
            make_batch("m-3", 2),
        ];
        batches[1].produced_at = earlier_time(); // 最早生产时间来自中间元素

        let new_id = BatchId::new("m-new");
        // at 为注入的记账时刻（晚于 earliest 也无妨，仅用于谱系边）
        let outcome = Batch::merge(&mut batches, new_id.clone(), producer(), fixed_time())
            .expect("同源合并应成功");

        let merged = &outcome.batch;
        assert_eq!(merged.id, new_id);
        assert_eq!(merged.quantity, 10, "合并后数量应为各父批之和");
        assert_eq!(merged.product, ProductId::new("p-milk"));
        assert_eq!(merged.unit, "box");
        assert_eq!(merged.producer, producer());
        assert_eq!(
            merged.produced_at,
            earlier_time(),
            "produced_at 应内部取 min(children.produced_at)"
        );
        assert_eq!(merged.state, LifecycleState::Created, "新批初始 Created");
        assert!(merged.active, "新批初始有效");

        // 全部父批失效
        assert!(batches.iter().all(|b| !b.active), "合并后所有父批都应失效");

        // 谱系边：每父批一条，op=Merge，方向 parent→new，时间戳取注入时钟
        assert_eq!(outcome.edges.len(), 3);
        for (edge, parent) in outcome.edges.iter().zip(batches.iter()) {
            assert_eq!(edge.parent, parent.id);
            assert_eq!(edge.child, new_id);
            assert_eq!(edge.op, LineageOp::Merge);
            assert_eq!(edge.at, fixed_time(), "谱系边时间戳应使用注入时钟");
        }
    }

    #[test]
    fn merge_inherits_compliance_conservatively() {
        // 全部父批合规 → 新批合规
        let mut all_ok = vec![make_batch("ok-1", 4), make_batch("ok-2", 6)];
        for b in &mut all_ok {
            b.compliance_ok = true;
        }
        let outcome = Batch::merge(
            &mut all_ok,
            BatchId::new("ok-new"),
            producer(),
            fixed_time(),
        )
        .expect("同源合并应成功");
        assert!(outcome.batch.compliance_ok);

        // 任一父批不合规 → 新批不合规（保守策略）
        let mut mixed = vec![make_batch("mx-1", 4), make_batch("mx-2", 6)];
        mixed[0].compliance_ok = true;
        let outcome = Batch::merge(&mut mixed, BatchId::new("mx-new"), producer(), fixed_time())
            .expect("同源合并应成功");
        assert!(!outcome.batch.compliance_ok);
    }

    #[test]
    fn merge_empty_parents_is_invalid_input() {
        let mut none: Vec<Batch> = Vec::new();
        let err = Batch::merge(&mut none, BatchId::new("n"), producer(), fixed_time())
            .expect_err("空列表必须被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)), "{err:?}");
    }

    // ---- 5. 合并异常路径 ----

    #[test]
    fn merge_rejects_different_products_units_or_producers() {
        // 不同商品类型
        let mut batches = vec![make_batch("d-1", 3), make_batch("d-2", 5)];
        batches[1].product = ProductId::new("p-other");
        let err = Batch::merge(
            &mut batches,
            BatchId::new("d-new"),
            producer(),
            fixed_time(),
        )
        .expect_err("不同商品类型必须被拒绝");
        assert!(
            matches!(&err, DomainError::InvalidInput(msg) if msg.contains("商品类型")),
            "{err:?}"
        );

        // 不同计量单位
        let mut batches = vec![make_batch("u-1", 3), make_batch("u-2", 5)];
        batches[1].unit = "kg".into();
        let err = Batch::merge(
            &mut batches,
            BatchId::new("u-new"),
            producer(),
            fixed_time(),
        )
        .expect_err("不同计量单位必须被拒绝");
        assert!(
            matches!(&err, DomainError::InvalidInput(msg) if msg.contains("计量单位")),
            "{err:?}"
        );

        // 不同生产者
        let mut batches = vec![make_batch("pr-1", 3), make_batch("pr-2", 5)];
        batches[1].producer = Did::parse("did:vg:user:factory-2").unwrap();
        let err = Batch::merge(
            &mut batches,
            BatchId::new("pr-new"),
            producer(),
            fixed_time(),
        )
        .expect_err("不同生产者必须被拒绝");
        assert!(
            matches!(&err, DomainError::InvalidInput(msg) if msg.contains("生产者")),
            "{err:?}"
        );
    }

    #[test]
    fn merge_rejects_inactive_or_terminal_parents_with_chinese_reasons() {
        // 存在失效父批
        let mut batches = vec![make_batch("ia-1", 3), make_batch("ia-2", 5)];
        batches[1].active = false;
        let err = Batch::merge(
            &mut batches,
            BatchId::new("ia-new"),
            producer(),
            fixed_time(),
        )
        .expect_err("含失效父批必须被拒绝");
        assert!(
            matches!(&err, DomainError::InvalidInput(msg) if msg.contains("失效") || msg.contains("无效")),
            "应带中文原因：{err:?}"
        );

        // 存在终态父批
        let mut batches = vec![make_batch("tm-1", 3), make_batch("tm-2", 5)];
        batches[1].state = LifecycleState::Expired;
        let err = Batch::merge(
            &mut batches,
            BatchId::new("tm-new"),
            producer(),
            fixed_time(),
        )
        .expect_err("含终态父批必须被拒绝");
        assert!(
            matches!(err, DomainError::InvalidTransition { ref to, .. } if to.contains("合并")),
            "终态违规应为 InvalidTransition 且带中文说明：{err:?}"
        );
    }

    // ---- 6. 溢出守恒 ----

    #[test]
    fn split_child_quantities_overflowing_u64_is_quantity_mismatch() {
        let mut parent = make_batch("ov-p", 10);
        // u64::MAX + u64::MAX 溢出：checked 求和不得回绕/panic，必须按数量不一致拒绝
        let err = parent
            .split(
                &[
                    (BatchId::new("ov-a"), u64::MAX),
                    (BatchId::new("ov-b"), u64::MAX),
                ],
                fixed_time(),
            )
            .expect_err("子批数量求和溢出应视为数量不一致");
        assert!(matches!(err, DomainError::QuantityMismatch), "{err:?}");
        assert!(parent.active, "失败的拆分不应改变父批状态");
    }

    #[test]
    fn merge_total_quantity_overflowing_u64_is_invalid_input() {
        let mut batches = vec![make_batch("om-1", u64::MAX), make_batch("om-2", u64::MAX)];
        let err = Batch::merge(
            &mut batches,
            BatchId::new("om-new"),
            producer(),
            fixed_time(),
        )
        .expect_err("合并总量溢出 u64 必须被拒绝");
        assert!(
            matches!(&err, DomainError::InvalidInput(msg) if msg.contains("溢出")),
            "实际错误：{err:?}"
        );
    }

    // ---- 7. serde 回环 ----

    #[test]
    fn serde_roundtrip_preserves_all_fields() {
        let mut batch = make_batch("sr-1", 42);
        batch.compliance_ok = true;
        batch.state = LifecycleState::InWarehouse;

        let text = serde_json::to_string(&batch).expect("序列化应成功");
        let back: Batch = serde_json::from_str(&text).expect("反序列化应成功");
        assert_eq!(back, batch, "serde 往返后字段必须完全一致");
    }
}
