//! 商品生命周期状态机。
//!
//! [`LifecycleState`] 定义批次/单品从建档到退出市场的 **12 个状态**；
//! [`ALLOWED_TRANSITIONS`] 物化全部合法迁移边（基础业务矩阵 + 监管强制路径），
//! [`can_transition`] / [`assert_transition`] 是唯一的迁移裁决入口——上层服务与
//! [`super::event::LifecycleEvent`] 的构造都必须经过它。
//!
//! ## 迁移规则速览
//!
//! 基础矩阵（业务驱动）：
//!
//! ```text
//! Created     → Produced
//! Produced    → Inspected | InTransit | InWarehouse | Destroyed
//! Inspected   → InTransit | InWarehouse | Available | Recalled
//! InTransit   → InWarehouse | Available
//! InWarehouse → Available | InTransit
//! Available   → Sold | Recalled | Expired
//! Sold        → Owned
//! Owned       → Resold | Recalled
//! ```
//!
//! 全局强制路径（监管驱动）：**任何非终态**均可 `→ Recalled`、`→ Destroyed`
//! （如问题批次无论处于哪个环节都可被强制召回，进而销毁）。
//! 终态：`Expired` 与 `Destroyed` 不可迁出；自迁移（from == to）一律禁止。

use serde::{Deserialize, Serialize};

use crate::shared::DomainError;

/// 商品（批次/单品）的生命周期状态（12 态全量）。
///
/// serde 序列化为小写蛇形：`"created"` / `"in_transit"` 等；
/// 中文名见 [`LifecycleState::zh_name`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// 创建（档案建立，尚未生产）。
    Created,
    /// 已生产。
    Produced,
    /// 已检验。
    Inspected,
    /// 运输中。
    InTransit,
    /// 在库。
    InWarehouse,
    /// 可售。
    Available,
    /// 已售出。
    Sold,
    /// 已持有（买家收货持有中）。
    Owned,
    /// 转售中。
    Resold,
    /// 已召回。
    Recalled,
    /// 已过期（终态，不可迁出）。
    Expired,
    /// 已销毁（终态，不可迁出）。
    Destroyed,
}

impl LifecycleState {
    /// 全部状态，按声明顺序排列（供穷举校验与遍历使用）。
    pub const ALL: [LifecycleState; 12] = [
        Self::Created,
        Self::Produced,
        Self::Inspected,
        Self::InTransit,
        Self::InWarehouse,
        Self::Available,
        Self::Sold,
        Self::Owned,
        Self::Resold,
        Self::Recalled,
        Self::Expired,
        Self::Destroyed,
    ];

    /// snake_case 名称，与 serde 序列化结果一致。
    pub fn as_str(&self) -> &'static str {
        match self {
            LifecycleState::Created => "created",
            LifecycleState::Produced => "produced",
            LifecycleState::Inspected => "inspected",
            LifecycleState::InTransit => "in_transit",
            LifecycleState::InWarehouse => "in_warehouse",
            LifecycleState::Available => "available",
            LifecycleState::Sold => "sold",
            LifecycleState::Owned => "owned",
            LifecycleState::Resold => "resold",
            LifecycleState::Recalled => "recalled",
            LifecycleState::Expired => "expired",
            LifecycleState::Destroyed => "destroyed",
        }
    }

    /// 中文名称，用于面向用户的错误信息与审计日志。
    pub fn zh_name(&self) -> &'static str {
        match self {
            LifecycleState::Created => "创建",
            LifecycleState::Produced => "已生产",
            LifecycleState::Inspected => "已检验",
            LifecycleState::InTransit => "运输中",
            LifecycleState::InWarehouse => "在库",
            LifecycleState::Available => "可售",
            LifecycleState::Sold => "已售出",
            LifecycleState::Owned => "已持有",
            LifecycleState::Resold => "转售中",
            LifecycleState::Recalled => "已召回",
            LifecycleState::Expired => "已过期",
            LifecycleState::Destroyed => "已销毁",
        }
    }

    /// 是否终态：`Expired` 与 `Destroyed` 不可迁出。
    pub fn is_terminal(&self) -> bool {
        matches!(self, LifecycleState::Expired | LifecycleState::Destroyed)
    }
}

impl std::fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 合法迁移边表：基础业务矩阵 + 全局强制路径的完整物化。
///
/// 裁决只认这张表（单一事实来源）；表中每条边都由穷举测试对照
/// 显式期望集合逐一钉死，改动任何一条都会被测试捕获。
///
/// 说明：
/// - 基础矩阵之外的两条全局强制路径（任何非终态 `→ Recalled` /
///   `→ Destroyed`）已展开为具体边写入表中（标注“监管强制”）；
/// - 终态无出边、无自迁移，因此这两类组合天然不在表中。
pub const ALLOWED_TRANSITIONS: &[(LifecycleState, LifecycleState)] = &[
    // ---- 基础业务矩阵 ----
    (LifecycleState::Created, LifecycleState::Produced),
    (LifecycleState::Produced, LifecycleState::Inspected),
    (LifecycleState::Produced, LifecycleState::InTransit),
    (LifecycleState::Produced, LifecycleState::InWarehouse),
    (LifecycleState::Produced, LifecycleState::Destroyed),
    (LifecycleState::Inspected, LifecycleState::InTransit),
    (LifecycleState::Inspected, LifecycleState::InWarehouse),
    (LifecycleState::Inspected, LifecycleState::Available),
    (LifecycleState::Inspected, LifecycleState::Recalled),
    (LifecycleState::InTransit, LifecycleState::InWarehouse),
    (LifecycleState::InTransit, LifecycleState::Available),
    (LifecycleState::InWarehouse, LifecycleState::Available),
    (LifecycleState::InWarehouse, LifecycleState::InTransit),
    (LifecycleState::Available, LifecycleState::Sold),
    (LifecycleState::Available, LifecycleState::Recalled),
    (LifecycleState::Available, LifecycleState::Expired),
    (LifecycleState::Sold, LifecycleState::Owned),
    (LifecycleState::Owned, LifecycleState::Resold),
    (LifecycleState::Owned, LifecycleState::Recalled),
    // ---- 全局强制路径补充（监管强制：任何非终态 → Recalled / → Destroyed；
    //      已在基础矩阵中的不重复收录，自迁移一律排除）----
    (LifecycleState::Created, LifecycleState::Recalled), // 监管强制
    (LifecycleState::Created, LifecycleState::Destroyed), // 监管强制
    (LifecycleState::Produced, LifecycleState::Recalled), // 监管强制
    (LifecycleState::Inspected, LifecycleState::Destroyed), // 监管强制
    (LifecycleState::InTransit, LifecycleState::Recalled), // 监管强制
    (LifecycleState::InTransit, LifecycleState::Destroyed), // 监管强制
    (LifecycleState::InWarehouse, LifecycleState::Recalled), // 监管强制
    (LifecycleState::InWarehouse, LifecycleState::Destroyed), // 监管强制
    (LifecycleState::Available, LifecycleState::Destroyed), // 监管强制
    (LifecycleState::Sold, LifecycleState::Recalled),    // 监管强制
    (LifecycleState::Sold, LifecycleState::Destroyed),   // 监管强制
    (LifecycleState::Owned, LifecycleState::Destroyed),  // 监管强制
    (LifecycleState::Resold, LifecycleState::Recalled),  // 监管强制
    (LifecycleState::Resold, LifecycleState::Destroyed), // 监管强制
    (LifecycleState::Recalled, LifecycleState::Destroyed), // 监管强制
];

/// 判断 `from → to` 是否为合法迁移。
///
/// 规则：查 [`ALLOWED_TRANSITIONS`] 边表；终态不可迁出、自迁移一律拒绝
/// （两者均已由边表内容保证，此处再显式短路以让不变式在代码中可读）。
pub fn can_transition(from: LifecycleState, to: LifecycleState) -> bool {
    if from == to || from.is_terminal() {
        return false;
    }
    ALLOWED_TRANSITIONS.contains(&(from, to))
}

/// 断言 `from → to` 合法，非法时返回带 from/to 信息的
/// [`DomainError::InvalidTransition`]（中文 Display 由错误类型自带）。
pub fn assert_transition(from: LifecycleState, to: LifecycleState) -> Result<(), DomainError> {
    if can_transition(from, to) {
        return Ok(());
    }
    Err(DomainError::InvalidTransition {
        from: format!("{}({})", from.zh_name(), from),
        to: format!("{}({})", to.zh_name(), to),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全部 12 态的期望三元组：(状态, serde 小写蛇形名, 中文名)。
    const EXPECTED: [(LifecycleState, &str, &str); 12] = [
        (LifecycleState::Created, "created", "创建"),
        (LifecycleState::Produced, "produced", "已生产"),
        (LifecycleState::Inspected, "inspected", "已检验"),
        (LifecycleState::InTransit, "in_transit", "运输中"),
        (LifecycleState::InWarehouse, "in_warehouse", "在库"),
        (LifecycleState::Available, "available", "可售"),
        (LifecycleState::Sold, "sold", "已售出"),
        (LifecycleState::Owned, "owned", "已持有"),
        (LifecycleState::Resold, "resold", "转售中"),
        (LifecycleState::Recalled, "recalled", "已召回"),
        (LifecycleState::Expired, "expired", "已过期"),
        (LifecycleState::Destroyed, "destroyed", "已销毁"),
    ];

    /// 规格矩阵 + 两条全局强制路径的**显式期望集合**（独立于实现硬编码，
    /// 不从 `ALLOWED_TRANSITIONS` 推导，防止实现与期望同源漂移）。
    fn expected_targets(from: LifecycleState) -> &'static [LifecycleState] {
        use LifecycleState::*;
        match from {
            Created => &[Produced, Recalled, Destroyed],
            Produced => &[Inspected, InTransit, InWarehouse, Recalled, Destroyed],
            Inspected => &[InTransit, InWarehouse, Available, Recalled, Destroyed],
            InTransit => &[InWarehouse, Available, Recalled, Destroyed],
            InWarehouse => &[Available, InTransit, Recalled, Destroyed],
            Available => &[Sold, Recalled, Expired, Destroyed],
            Sold => &[Owned, Recalled, Destroyed],
            Owned => &[Resold, Recalled, Destroyed],
            // 转售中仍属非终态：仅剩监管强制两条路
            Resold => &[Recalled, Destroyed],
            // 已召回非终态：仅剩监管销毁一条路（自迁移禁止）
            Recalled => &[Destroyed],
            Expired => &[],
            Destroyed => &[],
        }
    }

    // ---- 1. 144 组合穷举 ----

    #[test]
    fn exhaustive_144_combinations_match_expected_matrix() {
        let mut checked = 0usize;
        for from in LifecycleState::ALL {
            for to in LifecycleState::ALL {
                checked += 1;
                let expected = expected_targets(from).contains(&to);
                assert_eq!(
                    can_transition(from, to),
                    expected,
                    "{from:?}→{to:?} 与期望矩阵不符"
                );
                // assert_transition 与 can_transition 必须逐组合一致
                match assert_transition(from, to) {
                    Ok(()) => assert!(expected, "{from:?}→{to:?} 不应被允许"),
                    Err(err @ DomainError::InvalidTransition { .. }) => {
                        assert!(!expected, "{from:?}→{to:?} 应当被允许");
                        // 中文 Display 同时携带 snake_case 名与中文名
                        let msg = err.to_string();
                        assert!(msg.contains("非法状态迁移"), "实际消息：{msg}");
                        assert!(
                            msg.contains(from.as_str()) && msg.contains(to.as_str()),
                            "实际消息缺少状态名：{msg}"
                        );
                        assert!(
                            msg.contains(from.zh_name()) && msg.contains(to.zh_name()),
                            "实际消息缺少中文名：{msg}"
                        );
                    }
                    Err(other) => panic!("意外错误类型：{other}"),
                }
            }
        }
        assert_eq!(checked, 144, "必须穷举 12×12 组合");
    }

    /// 边表常量本身必须与期望集合**恰好相等**：不多、不少、不重复。
    #[test]
    fn allowed_transitions_table_equals_expected_edge_set_exactly() {
        // 表中每条边都落在期望集合内
        for &(from, to) in ALLOWED_TRANSITIONS {
            assert!(
                expected_targets(from).contains(&to),
                "边表出现规格之外的边：{from:?}→{to:?}"
            );
        }
        // 无重复边
        let mut sorted = ALLOWED_TRANSITIONS.to_vec();
        sorted.sort_by_key(|&(from, to)| (from.as_str(), to.as_str()));
        sorted.dedup();
        assert_eq!(sorted.len(), ALLOWED_TRANSITIONS.len(), "边表不得有重复边");
        // 期望集合中的每条边也在表内（双向一致），并核对总边数
        let mut total_expected = 0usize;
        for from in LifecycleState::ALL {
            for to in expected_targets(from) {
                total_expected += 1;
                assert!(
                    ALLOWED_TRANSITIONS.contains(&(from, *to)),
                    "期望边缺失于边表：{from:?}→{to:?}"
                );
            }
        }
        assert_eq!(ALLOWED_TRANSITIONS.len(), total_expected);
        assert_eq!(
            total_expected, 34,
            "应为 19 条基础矩阵边 + 15 条全局强制补充边"
        );
    }

    // ---- 2. 终态锁定 ----

    #[test]
    fn terminal_states_have_zero_outgoing_edges() {
        // 期望集合层面：出边为空
        assert_eq!(expected_targets(LifecycleState::Expired).len(), 0);
        assert_eq!(expected_targets(LifecycleState::Destroyed).len(), 0);
        // 行为层面：任何迁出都被拒绝（含自迁移）
        for from in [LifecycleState::Expired, LifecycleState::Destroyed] {
            for to in LifecycleState::ALL {
                assert!(
                    !can_transition(from, to),
                    "{from:?} 为终态，不允许迁出到 {to:?}"
                );
                assert!(
                    assert_transition(from, to).is_err(),
                    "{from:?} 为终态，assert 不应放行"
                );
            }
        }
        // 数据层面：边表中不存在以终态为源的边
        for &(from, _) in ALLOWED_TRANSITIONS {
            assert!(!from.is_terminal(), "终态 {from:?} 不应有出边");
        }
    }

    #[test]
    fn only_expired_and_destroyed_are_terminal() {
        for state in LifecycleState::ALL {
            match state {
                LifecycleState::Expired | LifecycleState::Destroyed => {
                    assert!(state.is_terminal(), "{state:?} 应为终态");
                }
                other => assert!(!other.is_terminal(), "{other:?} 不应是终态"),
            }
        }
    }

    #[test]
    fn self_transitions_are_always_forbidden() {
        for state in LifecycleState::ALL {
            assert!(!can_transition(state, state), "{state:?} 不允许自迁移");
        }
    }

    // ---- 3. 全局强制路径 ----

    #[test]
    fn regulator_forced_paths_allowed_from_every_non_terminal_state() {
        // 两条全局强制路径对每个非终态都必须可用（自迁移除外）
        for forced_to in [LifecycleState::Recalled, LifecycleState::Destroyed] {
            for from in LifecycleState::ALL {
                if from.is_terminal() || from == forced_to {
                    continue;
                }
                assert!(
                    can_transition(from, forced_to),
                    "非终态 {from:?} 应可被监管强制 {forced_to:?}"
                );
                assert_transition(from, forced_to)
                    .unwrap_or_else(|err| panic!("{from:?}→{forced_to:?}：{err}"));
            }
        }
        // 规格点名的三条代表性路径
        for (from, to) in [
            (LifecycleState::Produced, LifecycleState::Recalled),
            (LifecycleState::Sold, LifecycleState::Destroyed),
            (LifecycleState::Inspected, LifecycleState::Recalled),
        ] {
            assert_transition(from, to).expect("监管强制路径应放行");
        }
    }

    // ---- 4. 基础矩阵代表路径 ----

    #[test]
    fn happy_path_chain_is_fully_walkable() {
        // 从建档到转售召回再到销毁的一条完整链，每步都必须合法
        let chain = [
            (LifecycleState::Created, LifecycleState::Produced),
            (LifecycleState::Produced, LifecycleState::Inspected),
            (LifecycleState::Inspected, LifecycleState::Available),
            (LifecycleState::Available, LifecycleState::Sold),
            (LifecycleState::Sold, LifecycleState::Owned),
            (LifecycleState::Owned, LifecycleState::Resold),
            (LifecycleState::Resold, LifecycleState::Recalled),
            (LifecycleState::Recalled, LifecycleState::Destroyed),
        ];
        for (from, to) in chain {
            assert!(can_transition(from, to), "{from:?}→{to:?} 应合法");
        }
        // 反向哨兵：典型越级跳转必须拒绝
        for (from, to) in [
            (LifecycleState::Created, LifecycleState::Sold),
            (LifecycleState::Created, LifecycleState::Available),
            (LifecycleState::Available, LifecycleState::InWarehouse),
            (LifecycleState::Expired, LifecycleState::Produced),
        ] {
            assert!(!can_transition(from, to), "{from:?}→{to:?} 应非法");
        }
    }

    // ---- 5. serde / as_str / zh_name ----

    #[test]
    fn serde_snake_case_as_str_and_zh_name_cover_all_12_states() {
        // EXPECTED 与 LifecycleState::ALL 互相覆盖（防漏防多）
        assert_eq!(EXPECTED.len(), 12);
        assert_eq!(LifecycleState::ALL.len(), 12);
        for (state, _, _) in EXPECTED {
            assert!(LifecycleState::ALL.contains(&state), "{state:?} 未纳入 ALL");
        }

        let mut zh_names: Vec<&str> = Vec::new();
        for (state, name, zh) in EXPECTED {
            // serde 序列化 == 小写蛇形 == as_str == Display
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{name}\""),
                "{state:?} 序列化不符"
            );
            assert_eq!(state.as_str(), name);
            assert_eq!(state.to_string(), name);
            // 反序列化回环
            let back: LifecycleState =
                serde_json::from_str(&format!("\"{name}\"")).expect("应可反序列化");
            assert_eq!(back, state);
            // 中文名
            assert_eq!(state.zh_name(), zh);
            zh_names.push(state.zh_name());
        }
        // 中文名互不相同且非空（错误信息可区分）
        assert!(zh_names.iter().all(|name| !name.is_empty()));
        zh_names.sort_unstable();
        zh_names.dedup();
        assert_eq!(zh_names.len(), 12, "中文名应互不相同");

        // 未知字符串与大小写变体一律拒绝
        assert!(serde_json::from_str::<LifecycleState>("\"lost\"").is_err());
        assert!(serde_json::from_str::<LifecycleState>("\"Created\"").is_err());
        assert!(serde_json::from_str::<LifecycleState>("\"in-transit\"").is_err());
    }
}
