//! 批次谱系：拆分/合并/加工形成的父子关系边。
//!
//! 谱系边是不可变事实：`parent` 批次经过 [`LineageOp`] 操作于 `at` 时刻
//! 产生 `child` 批次。拆分与合并成功时由 [`super::batch`] 产出应记录的
//! 边集合，由应用层经 [`super::ports::CommodityRepository::save_lineage`]
//! 持久化。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::shared::BatchId;

/// 谱系边的操作类型；serde 序列化为小写蛇形：
/// `"split"` / `"merge"` / `"transform"`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageOp {
    /// 拆分：一个父批次分成多个子批次（数量守恒）。
    Split,
    /// 合并：多个同源父批次并为一个子批次（数量守恒）。
    Merge,
    /// 加工/转换：输入批次转化为输出批次（数量可不守恒，由凭证背书）。
    Transform,
}

/// 一条谱系边：`parent` 经 `op` 操作于 `at` 时刻产生 `child`。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LineageEdge {
    /// 父批次。
    pub parent: BatchId,
    /// 子批次。
    pub child: BatchId,
    /// 产生该边的操作。
    pub op: LineageOp,
    /// 操作发生时刻。
    pub at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn lineage_op_serializes_as_lowercase_snake_case() {
        for (op, name) in [
            (LineageOp::Split, "split"),
            (LineageOp::Merge, "merge"),
            (LineageOp::Transform, "transform"),
        ] {
            assert_eq!(
                serde_json::to_string(&op).unwrap(),
                format!("\"{name}\""),
                "{op:?} 序列化应为小写蛇形"
            );
            let back: LineageOp =
                serde_json::from_str(&format!("\"{name}\"")).expect("应可反序列化");
            assert_eq!(back, op);
        }
        // 未知字符串与大写变体一律拒绝
        assert!(serde_json::from_str::<LineageOp>("\"fork\"").is_err());
        assert!(serde_json::from_str::<LineageOp>("\"Split\"").is_err());
    }

    #[test]
    fn lineage_edge_roundtrips_through_json() {
        let edge = LineageEdge {
            parent: BatchId::new("b-parent"),
            child: BatchId::new("b-child"),
            op: LineageOp::Merge,
            at: Utc.with_ymd_and_hms(2026, 8, 25, 12, 0, 0).unwrap(),
        };
        let text = serde_json::to_string(&edge).expect("序列化应成功");
        assert!(text.contains("\"parent\":\"b-parent\""), "实际：{text}");
        assert!(text.contains("\"op\":\"merge\""), "实际：{text}");
        let back: LineageEdge = serde_json::from_str(&text).expect("反序列化应成功");
        assert_eq!(back, edge);
    }
}
