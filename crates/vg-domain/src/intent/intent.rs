//! Intent 聚合：动作、风险分级与状态机。
//!
//! [`Intent`] 是全系统**唯一的写入口径**——任何改变链上/链下状态的业务动作
//! 都必须先落为一条 Intent，经管道逐级推进后才能被执行（设计文档 §4/§27）。
//!
//! 管道（与 [`IntentStatus`] 各阶段一一对应）：
//!
//! ```text
//! Created → Validated → Authorized → PolicyChecked →(ProofRequired → Proved)→ Approved
//!         → Submitted → Confirmed
//! ```
//!
//! 任一非终态可进入 `Rejected` / `Expired` / `Cancelled`；
//! 但 `Submitted` 之后账本受理在途，仅可 `→ Confirmed | Rejected | Expired`（不可取消）。
//!
//! 风险分级 [`RiskLevel`]（§40）决定管道的审批形态：L1 自动执行（读/验）、
//! L2 企业策略自动批准、L3 额外授权、L4 监管多签人工审批。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::shared::{Did, DomainError, IntentId};

/// Intent 携带的业务动作（全系统写动作的封闭枚举）。
///
/// serde 序列化为小写蛇形：`"create_batch"` / `"transfer_product"` 等。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentAction {
    /// 创建批次。
    CreateBatch,
    /// 拆分批次。
    SplitBatch,
    /// 合并批次。
    MergeBatch,
    /// 批次加工转化。
    TransformBatch,
    /// 创建单品。
    CreateItem,
    /// 转移产品（含所有权转移）。
    TransferProduct,
    /// 更新保管信息。
    UpdateCustody,
    /// 签发凭证。
    IssueCredential,
    /// 撤销凭证。
    RevokeCredential,
    /// 合规检查（读/验类）。
    ComplianceCheck,
    /// 隐私模式下的受屏蔽转移（Shielded Transactions）。
    ShieldedTransfer,
    /// 提交状态根（Private Validium）。
    SubmitStateRoot,
    /// mass recall，批量召回。
    MassRecall,
}

impl IntentAction {
    /// 全部动作，按声明顺序（供穷举测试遍历）。
    pub const ALL: [IntentAction; 13] = [
        Self::CreateBatch,
        Self::SplitBatch,
        Self::MergeBatch,
        Self::TransformBatch,
        Self::CreateItem,
        Self::TransferProduct,
        Self::UpdateCustody,
        Self::IssueCredential,
        Self::RevokeCredential,
        Self::ComplianceCheck,
        Self::ShieldedTransfer,
        Self::SubmitStateRoot,
        Self::MassRecall,
    ];

    /// snake_case 名称，与 serde 序列化结果一致。
    pub fn as_str(&self) -> &'static str {
        match self {
            IntentAction::CreateBatch => "create_batch",
            IntentAction::SplitBatch => "split_batch",
            IntentAction::MergeBatch => "merge_batch",
            IntentAction::TransformBatch => "transform_batch",
            IntentAction::CreateItem => "create_item",
            IntentAction::TransferProduct => "transfer_product",
            IntentAction::UpdateCustody => "update_custody",
            IntentAction::IssueCredential => "issue_credential",
            IntentAction::RevokeCredential => "revoke_credential",
            IntentAction::ComplianceCheck => "compliance_check",
            IntentAction::ShieldedTransfer => "shielded_transfer",
            IntentAction::SubmitStateRoot => "submit_state_root",
            IntentAction::MassRecall => "mass_recall",
        }
    }

    /// 按设计文档 §40 映射的风险分级：
    ///
    /// - **L1**（读/验，自动执行）：`ComplianceCheck`；
    /// - **L2**（企业策略自动批准）：批次/单品建档与流转、凭证签撤、状态根提交；
    /// - **L3**（需额外授权）：所有权转移与受屏蔽转移；
    /// - **L4**（监管多签人工审批）：批量召回。
    pub fn risk_level(&self) -> RiskLevel {
        match self {
            IntentAction::ComplianceCheck => RiskLevel::L1,
            IntentAction::CreateBatch
            | IntentAction::SplitBatch
            | IntentAction::MergeBatch
            | IntentAction::TransformBatch
            | IntentAction::CreateItem
            | IntentAction::UpdateCustody
            | IntentAction::IssueCredential
            | IntentAction::RevokeCredential
            | IntentAction::SubmitStateRoot => RiskLevel::L2,
            IntentAction::TransferProduct | IntentAction::ShieldedTransfer => RiskLevel::L3,
            IntentAction::MassRecall => RiskLevel::L4,
        }
    }
}

impl std::fmt::Display for IntentAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 风险分级（§40）：决定 Intent 的审批管道形态。
///
/// serde 序列化为 `"l1"`..`"l4"`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// 读/验类，自动执行。
    L1,
    /// 企业策略自动批准。
    L2,
    /// 需额外授权（如所有权转移）。
    L3,
    /// 监管多签人工审批（召回/冻结）。
    L4,
}

impl RiskLevel {
    /// snake_case 名称，与 serde 序列化结果一致。
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::L1 => "l1",
            RiskLevel::L2 => "l2",
            RiskLevel::L3 => "l3",
            RiskLevel::L4 => "l4",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Intent 在管道中的推进状态（§27 有向图）。
///
/// serde 序列化为小写蛇形：`"proof_required"` / `"policy_checked"` 等。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    /// 已创建（Schema 校验前）。
    Created,
    /// Schema 校验通过。
    Validated,
    /// DID/Capability 授权通过。
    Authorized,
    /// Policy Engine 校验通过。
    PolicyChecked,
    /// 等待 ZK 证明（需要证明的动作）。
    ProofRequired,
    /// 证明已提交并验证。
    Proved,
    /// 已批准（无需证明的动作从 PolicyChecked 直达）。
    Approved,
    /// 已提交账本（LedgerPort 受理在途）。
    Submitted,
    /// 账本确认（终态）。
    Confirmed,
    /// 被拒绝（终态，携带 rejection 原因）。
    Rejected,
    /// 已过期（终态）。
    Expired,
    /// 已取消（终态）。
    Cancelled,
}

impl IntentStatus {
    /// 全部状态，按声明顺序（供穷举测试遍历）。
    pub const ALL: [IntentStatus; 12] = [
        Self::Created,
        Self::Validated,
        Self::Authorized,
        Self::PolicyChecked,
        Self::ProofRequired,
        Self::Proved,
        Self::Approved,
        Self::Submitted,
        Self::Confirmed,
        Self::Rejected,
        Self::Expired,
        Self::Cancelled,
    ];

    /// snake_case 名称，与 serde 序列化结果一致。
    pub fn as_str(&self) -> &'static str {
        match self {
            IntentStatus::Created => "created",
            IntentStatus::Validated => "validated",
            IntentStatus::Authorized => "authorized",
            IntentStatus::PolicyChecked => "policy_checked",
            IntentStatus::ProofRequired => "proof_required",
            IntentStatus::Proved => "proved",
            IntentStatus::Approved => "approved",
            IntentStatus::Submitted => "submitted",
            IntentStatus::Confirmed => "confirmed",
            IntentStatus::Rejected => "rejected",
            IntentStatus::Expired => "expired",
            IntentStatus::Cancelled => "cancelled",
        }
    }

    /// 是否终态：`Confirmed` / `Rejected` / `Expired` / `Cancelled` 不可再变。
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            IntentStatus::Confirmed | IntentStatus::Rejected | IntentStatus::Expired | IntentStatus::Cancelled
        )
    }
}

impl std::fmt::Display for IntentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 状态有向图的合法边表（§27）：管道正序 + 全局终局路径的完整物化。
///
/// 裁决只认这张表（单一事实来源）；穷举测试对照显式期望集合逐边钉死。
pub const ALLOWED_TRANSITIONS: &[(IntentStatus, IntentStatus)] = &[
    // ---- 管道正序 ----
    (IntentStatus::Created, IntentStatus::Validated),
    (IntentStatus::Validated, IntentStatus::Authorized),
    (IntentStatus::Authorized, IntentStatus::PolicyChecked),
    // 需要证明的动作走 ProofRequired → Proved；无需证明的动作直达 Approved
    (IntentStatus::PolicyChecked, IntentStatus::ProofRequired),
    (IntentStatus::PolicyChecked, IntentStatus::Approved),
    (IntentStatus::ProofRequired, IntentStatus::Proved),
    (IntentStatus::Proved, IntentStatus::Approved),
    (IntentStatus::Approved, IntentStatus::Submitted),
    (IntentStatus::Submitted, IntentStatus::Confirmed),
    // ---- 全局终局路径：任意非终态 → Rejected / Expired / Cancelled ----
    // （Submitted 例外：账本受理在途不可取消，仅可 Confirmed | Rejected | Expired）
    (IntentStatus::Created, IntentStatus::Rejected),
    (IntentStatus::Created, IntentStatus::Expired),
    (IntentStatus::Created, IntentStatus::Cancelled),
    (IntentStatus::Validated, IntentStatus::Rejected),
    (IntentStatus::Validated, IntentStatus::Expired),
    (IntentStatus::Validated, IntentStatus::Cancelled),
    (IntentStatus::Authorized, IntentStatus::Rejected),
    (IntentStatus::Authorized, IntentStatus::Expired),
    (IntentStatus::Authorized, IntentStatus::Cancelled),
    (IntentStatus::PolicyChecked, IntentStatus::Rejected),
    (IntentStatus::PolicyChecked, IntentStatus::Expired),
    (IntentStatus::PolicyChecked, IntentStatus::Cancelled),
    (IntentStatus::ProofRequired, IntentStatus::Rejected),
    (IntentStatus::ProofRequired, IntentStatus::Expired),
    (IntentStatus::ProofRequired, IntentStatus::Cancelled),
    (IntentStatus::Proved, IntentStatus::Rejected),
    (IntentStatus::Proved, IntentStatus::Expired),
    (IntentStatus::Proved, IntentStatus::Cancelled),
    (IntentStatus::Approved, IntentStatus::Rejected),
    (IntentStatus::Approved, IntentStatus::Expired),
    (IntentStatus::Approved, IntentStatus::Cancelled),
    (IntentStatus::Submitted, IntentStatus::Rejected),
    (IntentStatus::Submitted, IntentStatus::Expired),
];

/// 判断 `from → to` 是否为合法推进。
///
/// 终态不可迁出、自迁移一律拒绝（两者均由边表内容保证，此处显式短路以让不变式可读）。
pub fn can_transition(from: IntentStatus, to: IntentStatus) -> bool {
    if from == to || from.is_terminal() {
        return false;
    }
    ALLOWED_TRANSITIONS.contains(&(from, to))
}

/// 断言 `from → to` 合法，非法时返回 [`DomainError::InvalidTransition`]。
pub fn assert_transition(from: IntentStatus, to: IntentStatus) -> Result<(), DomainError> {
    if can_transition(from, to) {
        return Ok(());
    }
    Err(DomainError::InvalidTransition {
        from: from.to_string(),
        to: to.to_string(),
    })
}

/// Intent 聚合根：一次写请求的完整档案（动作、发起人、载荷与管道状态）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Intent {
    /// 唯一标识。
    pub id: IntentId,
    /// 业务动作。
    pub action: IntentAction,
    /// 发起人 DID。
    pub actor: Did,
    /// 代理发起时记录被代理企业的 DID（Agent 代企业发起；Agent 资格校验属 identity 上下文职责）。
    pub on_behalf_of: Option<Did>,
    /// 动作参数（JSON object，结构由各动作的 Schema 校验约束）。
    pub payload: serde_json::Value,
    /// 防重放单调值。
    pub nonce: u64,
    /// 创建时间。
    pub created_at: DateTime<Utc>,
    /// 过期时间（`now >= expires_at` 即失效，与全局过期边界语义一致）。
    pub expires_at: DateTime<Utc>,
    /// 管道推进状态。
    pub status: IntentStatus,
    /// 拒绝原因（仅 Rejected 终态有值）。
    pub rejection: Option<String>,
    /// 风险分级（由 action 按 §40 推导）。
    pub risk: RiskLevel,
    /// 执行结果引用（仅 Confirmed 终态有值，如链上交易哈希）。
    pub result_ref: Option<String>,
}

impl Intent {
    /// 构造新 Intent（status=Created，risk 由 action 推导）。
    ///
    /// 校验：payload 必须为 JSON object（与 VC claims 先例一致）；
    /// `expires_at` 必须晚于 `now`（防创建即过期）。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: IntentId,
        action: IntentAction,
        actor: Did,
        on_behalf_of: Option<Did>,
        payload: serde_json::Value,
        nonce: u64,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        if !payload.is_object() {
            return Err(DomainError::InvalidInput(format!(
                "Intent payload 必须为 JSON object，实际为 {}",
                payload_type_name(&payload)
            )));
        }
        if expires_at <= now {
            return Err(DomainError::InvalidInput(
                "Intent expires_at 必须晚于创建时刻".to_string(),
            ));
        }
        Ok(Self {
            risk: action.risk_level(),
            id,
            action,
            actor,
            on_behalf_of,
            payload,
            nonce,
            created_at: now,
            expires_at,
            status: IntentStatus::Created,
            rejection: None,
            result_ref: None,
        })
    }

    /// 按 §27 有向图推进状态；终态不可再变，非法跳转返回
    /// [`DomainError::InvalidTransition`]。
    pub fn advance(&mut self, to: IntentStatus) -> Result<(), DomainError> {
        assert_transition(self.status, to)?;
        self.status = to;
        Ok(())
    }

    /// 拒绝该 Intent：推进到 `Rejected` 并记录原因（仅当当前状态可进入 Rejected）。
    pub fn reject(&mut self, reason: impl Into<String>) -> Result<(), DomainError> {
        assert_transition(self.status, IntentStatus::Rejected)?;
        self.status = IntentStatus::Rejected;
        self.rejection = Some(reason.into());
        Ok(())
    }

    /// 确认该 Intent：推进到 `Confirmed` 并记录结果引用（如链上交易哈希）。
    pub fn confirm(&mut self, result_ref: impl Into<String>) -> Result<(), DomainError> {
        assert_transition(self.status, IntentStatus::Confirmed)?;
        self.status = IntentStatus::Confirmed;
        self.result_ref = Some(result_ref.into());
        Ok(())
    }

    /// 防重放安全窗口：`now < expires_at` 即可安全推进
    /// （过期边界统一为 `now >= expires_at` 即失效）。
    pub fn is_replay_safe(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }
}

/// payload 的 JSON 类型名（错误信息用；object 不会走到此处）。
fn payload_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn t() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn sample(
        action: IntentAction,
        payload: serde_json::Value,
    ) -> Result<Intent, DomainError> {
        Intent::new(
            IntentId::new("intent-001"),
            action,
            Did::parse("did:vg:user:alice").unwrap(),
            Some(Did::parse("did:vg:org:acme").unwrap()),
            payload,
            42,
            t(),
            t() + chrono::Duration::hours(1),
        )
    }

    /// 构造已推进到指定状态的 Intent（沿途逐步 advance）。
    fn at_status(status: IntentStatus) -> Intent {
        let mut intent = sample(IntentAction::CreateBatch, json!({"qty": 10})).unwrap();
        use IntentStatus::*;
        // 终局状态经合法边进入：Rejected/Cancelled 从 Created 直达，
        // Expired 走 Submitted→Expired 分支以顺带覆盖该边
        match status {
            Rejected | Cancelled => {
                intent.advance(status).expect("Created 直达终局应合法");
                return intent;
            }
            Expired => {
                for step in [Validated, Authorized, PolicyChecked, Approved, Submitted] {
                    intent.advance(step).expect("测试路径推进不应失败");
                }
                intent.advance(Expired).expect("Submitted→Expired 应合法");
                return intent;
            }
            _ => {}
        }
        let path = [
            Validated, Authorized, PolicyChecked, ProofRequired, Proved, Approved, Submitted,
            Confirmed,
        ];
        for step in path {
            if intent.status == status {
                break;
            }
            intent.advance(step).expect("测试路径推进不应失败");
        }
        assert_eq!(intent.status, status, "测试辅助应精确到达目标状态");
        intent
    }

    // ---- 1. 状态图穷举 ----

    /// 独立于实现的期望边集合（不从 ALLOWED_TRANSITIONS 推导，防同源漂移）。
    fn expected_targets(from: IntentStatus) -> &'static [IntentStatus] {
        use IntentStatus::*;
        match from {
            Created => &[Validated, Rejected, Expired, Cancelled],
            Validated => &[Authorized, Rejected, Expired, Cancelled],
            Authorized => &[PolicyChecked, Rejected, Expired, Cancelled],
            PolicyChecked => &[ProofRequired, Approved, Rejected, Expired, Cancelled],
            ProofRequired => &[Proved, Rejected, Expired, Cancelled],
            Proved => &[Approved, Rejected, Expired, Cancelled],
            Approved => &[Submitted, Rejected, Expired, Cancelled],
            // 提交账本后不可取消：仅确认/拒绝/过期
            Submitted => &[Confirmed, Rejected, Expired],
            Confirmed | Rejected | Expired | Cancelled => &[],
        }
    }

    #[test]
    fn exhaustive_144_combinations_match_expected_matrix() {
        let mut checked = 0usize;
        for from in IntentStatus::ALL {
            for to in IntentStatus::ALL {
                checked += 1;
                let expected = expected_targets(from).contains(&to);
                assert_eq!(
                    can_transition(from, to),
                    expected,
                    "{from:?}→{to:?} 与期望矩阵不符"
                );
                match assert_transition(from, to) {
                    Ok(()) => assert!(expected, "{from:?}→{to:?} 不应被允许"),
                    Err(err @ DomainError::InvalidTransition { .. }) => {
                        assert!(!expected, "{from:?}→{to:?} 应当被允许");
                        // from/to 用 as_str()
                        assert_eq!(
                            err.to_string(),
                            format!("非法状态迁移：{} -> {}", from.as_str(), to.as_str())
                        );
                    }
                    Err(other) => panic!("意外错误类型：{other}"),
                }
            }
        }
        assert_eq!(checked, 144, "必须穷举 12×12 组合");
    }

    /// 边表常量与期望集合恰好相等：不多、不少、不重复。
    #[test]
    fn allowed_transitions_table_equals_expected_edge_set_exactly() {
        for &(from, to) in ALLOWED_TRANSITIONS {
            assert!(
                expected_targets(from).contains(&to),
                "边表出现规格之外的边：{from:?}→{to:?}"
            );
        }
        let mut sorted = ALLOWED_TRANSITIONS.to_vec();
        sorted.sort_by_key(|&(from, to)| (from.as_str(), to.as_str()));
        sorted.dedup();
        assert_eq!(sorted.len(), ALLOWED_TRANSITIONS.len(), "边表不得有重复边");
        let mut total = 0usize;
        for from in IntentStatus::ALL {
            for to in expected_targets(from) {
                total += 1;
                assert!(
                    ALLOWED_TRANSITIONS.contains(&(from, *to)),
                    "期望边缺失于边表：{from:?}→{to:?}"
                );
            }
        }
        assert_eq!(ALLOWED_TRANSITIONS.len(), total);
        assert_eq!(total, 32, "9 条管道正序边 + 23 条终局路径边");
    }

    // ---- 2. 管道正序全链 ----

    #[test]
    fn pipeline_happy_path_walks_to_confirmed_step_by_step() {
        // 需要证明的动作：全链含 ProofRequired → Proved
        let mut intent = sample(IntentAction::TransferProduct, json!({"to": "bob"})).unwrap();
        for to in [
            IntentStatus::Validated,
            IntentStatus::Authorized,
            IntentStatus::PolicyChecked,
            IntentStatus::ProofRequired,
            IntentStatus::Proved,
            IntentStatus::Approved,
            IntentStatus::Submitted,
            IntentStatus::Confirmed,
        ] {
            intent.advance(to).unwrap_or_else(|e| panic!("推进到 {to:?} 失败：{e}"));
        }
        assert_eq!(intent.status, IntentStatus::Confirmed);
        assert!(intent.status.is_terminal());
    }

    #[test]
    fn policy_checked_can_short_circuit_to_approved_without_proof() {
        // 无需证明的动作：PolicyChecked → Approved 直通
        let mut intent = sample(IntentAction::CreateBatch, json!({"qty": 1})).unwrap();
        intent.advance(IntentStatus::Validated).unwrap();
        intent.advance(IntentStatus::Authorized).unwrap();
        intent.advance(IntentStatus::PolicyChecked).unwrap();
        intent.advance(IntentStatus::Approved).expect("直通分支应放行");
        assert_eq!(intent.status, IntentStatus::Approved);
        // 反向：Approved 不能回到 ProofRequired
        let mut i2 = sample(IntentAction::CreateBatch, json!({})).unwrap();
        i2.status = IntentStatus::Approved;
        assert!(i2.advance(IntentStatus::ProofRequired).is_err());
    }

    #[test]
    fn illegal_skips_are_rejected_with_correct_from_to() {
        for (from, to) in [
            (IntentStatus::Created, IntentStatus::Approved),
            (IntentStatus::Created, IntentStatus::Confirmed),
            (IntentStatus::Created, IntentStatus::Authorized), // 跳过 Validated
            (IntentStatus::Validated, IntentStatus::PolicyChecked),
            (IntentStatus::Authorized, IntentStatus::Approved),
            (IntentStatus::Proved, IntentStatus::Submitted),
        ] {
            let mut intent = sample(IntentAction::CreateBatch, json!({})).unwrap();
            intent.status = from;
            match intent.advance(to) {
                Err(DomainError::InvalidTransition { from: f, to: t }) => {
                    assert_eq!((f.as_str(), t.as_str()), (from.as_str(), to.as_str()));
                }
                other => panic!("{from:?}→{to:?} 应被拒绝，实际：{other:?}"),
            }
            assert_eq!(intent.status, from, "失败推进不得改变状态");
        }
    }

    // ---- 3. 终态锁定 ----

    #[test]
    fn terminal_states_are_locked_for_all_targets() {
        for from in [
            IntentStatus::Confirmed,
            IntentStatus::Rejected,
            IntentStatus::Expired,
            IntentStatus::Cancelled,
        ] {
            assert!(from.is_terminal(), "{from:?} 应为终态");
            for to in IntentStatus::ALL {
                assert!(!can_transition(from, to), "{from:?}→{to:?} 应全部拒绝");
            }
            let mut intent = at_status(from);
            // 换一种终态再推也不行（含 → 彼此）
            for to in [
                IntentStatus::Confirmed,
                IntentStatus::Rejected,
                IntentStatus::Expired,
                IntentStatus::Cancelled,
                IntentStatus::Created,
            ] {
                assert!(intent.advance(to).is_err(), "{from:?}→{to:?} 应拒绝");
            }
            assert_eq!(intent.status, from, "终态不可变");
        }
        // 非终态集合恰好是其余 8 个
        assert_eq!(
            IntentStatus::ALL.iter().filter(|s| !s.is_terminal()).count(),
            8
        );
    }

    #[test]
    fn submitted_cannot_cancel_but_can_reject_or_expire() {
        let mut intent = at_status(IntentStatus::Submitted);
        assert!(intent.advance(IntentStatus::Cancelled).is_err(), "提交后不可取消");
        assert_eq!(intent.status, IntentStatus::Submitted);
        intent.advance(IntentStatus::Rejected).expect("提交后仍可被拒绝");
        let mut intent2 = at_status(IntentStatus::Submitted);
        intent2.advance(IntentStatus::Expired).expect("提交后仍可过期");
    }

    // ---- 4. 风险分级 ----

    #[test]
    fn risk_level_covers_all_13_actions() {
        let expected = [
            (IntentAction::CreateBatch, RiskLevel::L2),
            (IntentAction::SplitBatch, RiskLevel::L2),
            (IntentAction::MergeBatch, RiskLevel::L2),
            (IntentAction::TransformBatch, RiskLevel::L2),
            (IntentAction::CreateItem, RiskLevel::L2),
            (IntentAction::TransferProduct, RiskLevel::L3),
            (IntentAction::UpdateCustody, RiskLevel::L2),
            (IntentAction::IssueCredential, RiskLevel::L2),
            (IntentAction::RevokeCredential, RiskLevel::L2),
            (IntentAction::ComplianceCheck, RiskLevel::L1),
            (IntentAction::ShieldedTransfer, RiskLevel::L3),
            (IntentAction::SubmitStateRoot, RiskLevel::L2),
            (IntentAction::MassRecall, RiskLevel::L4),
        ];
        for (action, risk) in expected {
            assert_eq!(action.risk_level(), risk, "{action:?} 分级不符");
        }
        // 四级全覆盖
        assert_eq!(IntentAction::ALL.len(), 13);
    }

    // ---- 5. Intent::new 校验 ----

    #[test]
    fn new_rejects_non_object_payload() {
        for payload in [json!(42), json!("str"), json!([1, 2]), json!(null), json!(true)] {
            let err = sample(IntentAction::CreateBatch, payload).unwrap_err();
            assert!(
                matches!(err, DomainError::InvalidInput(ref m) if m.contains("payload")),
                "应为 InvalidInput(payload)，实际：{err}"
            );
        }
    }

    #[test]
    fn new_rejects_already_expired_window() {
        let now = t();
        let err = Intent::new(
            IntentId::new("i"),
            IntentAction::CreateBatch,
            Did::parse("did:vg:user:alice").unwrap(),
            None,
            json!({}),
            1,
            now,
            now, // expires_at == now
        )
        .unwrap_err();
        assert!(matches!(err, DomainError::InvalidInput(_)), "实际：{err}");
        // 早于 now 同样拒绝
        let err2 = Intent::new(
            IntentId::new("i"),
            IntentAction::CreateBatch,
            Did::parse("did:vg:user:alice").unwrap(),
            None,
            json!({}),
            1,
            now,
            now - chrono::Duration::seconds(1),
        )
        .unwrap_err();
        assert!(matches!(err2, DomainError::InvalidInput(_)));
    }

    #[test]
    fn new_populates_all_fields() {
        let intent = sample(IntentAction::MassRecall, json!({"reason": "污染"})).unwrap();
        assert_eq!(intent.id, IntentId::new("intent-001"));
        assert_eq!(intent.action, IntentAction::MassRecall);
        assert_eq!(intent.actor, Did::parse("did:vg:user:alice").unwrap());
        assert_eq!(
            intent.on_behalf_of,
            Some(Did::parse("did:vg:org:acme").unwrap())
        );
        assert_eq!(intent.nonce, 42);
        assert_eq!(intent.created_at, t());
        assert_eq!(intent.expires_at, t() + chrono::Duration::hours(1));
        assert_eq!(intent.status, IntentStatus::Created);
        assert_eq!(intent.risk, RiskLevel::L4); // 由 action 推导
        assert!(intent.rejection.is_none());
        assert!(intent.result_ref.is_none());
    }

    // ---- 6. reject / confirm ----

    #[test]
    fn reject_records_reason_and_is_gated_by_transition() {
        let mut intent = sample(IntentAction::CreateBatch, json!({})).unwrap();
        intent
            .reject("凭证缺失")
            .expect("Created 可进入 Rejected");
        assert_eq!(intent.status, IntentStatus::Rejected);
        assert_eq!(intent.rejection.as_deref(), Some("凭证缺失"));
        // 终态再 reject 拒绝
        assert!(intent.reject("再次拒绝").is_err());
        assert_eq!(intent.rejection.as_deref(), Some("凭证缺失"), "原因不得被覆盖");

        // Submitted 仍可拒绝
        let mut submitted = at_status(IntentStatus::Submitted);
        submitted.reject("账本拒绝").expect("Submitted 可进入 Rejected");
        assert_eq!(submitted.rejection.as_deref(), Some("账本拒绝"));

        // Confirmed 终态不可 reject
        let mut confirmed = at_status(IntentStatus::Confirmed);
        assert!(confirmed.reject("事后拒绝").is_err());
    }

    #[test]
    fn confirm_records_result_ref() {
        let mut intent = at_status(IntentStatus::Submitted);
        intent.confirm("0xabc123").expect("Submitted 可确认");
        assert_eq!(intent.status, IntentStatus::Confirmed);
        assert_eq!(intent.result_ref.as_deref(), Some("0xabc123"));
        // 非 Submitted 的前置状态不能直接 confirm
        let mut early = sample(IntentAction::CreateBatch, json!({})).unwrap();
        assert!(early.confirm("0x").is_err());
    }

    // ---- 7. is_replay_safe ----

    #[test]
    fn replay_safe_window_respects_expiry_boundary() {
        let intent = sample(IntentAction::CreateBatch, json!({})).unwrap();
        let expires = intent.expires_at;
        assert!(intent.is_replay_safe(expires - chrono::Duration::seconds(1)));
        assert!(!intent.is_replay_safe(expires), "now == expires_at 即失效");
        assert!(!intent.is_replay_safe(expires + chrono::Duration::seconds(1)));
    }

    // ---- 8. serde ----

    #[test]
    fn intent_roundtrips_through_serde_json() {
        let mut intent = sample(IntentAction::ShieldedTransfer, json!({"note": "n"})).unwrap();
        intent.advance(IntentStatus::Validated).unwrap();
        let text = serde_json::to_string(&intent).unwrap();
        let back: Intent = serde_json::from_str(&text).unwrap();
        assert_eq!(back, intent);

        // 终态字段也参与 roundtrip
        let mut rejected = sample(IntentAction::MassRecall, json!({})).unwrap();
        rejected.reject("监管驳回").unwrap();
        let back2: Intent = serde_json::from_str(&serde_json::to_string(&rejected).unwrap()).unwrap();
        assert_eq!(back2, rejected);
    }

    #[test]
    fn enums_serialize_snake_case_and_reject_unknown() {
        assert_eq!(
            serde_json::to_string(&IntentStatus::ProofRequired).unwrap(),
            "\"proof_required\""
        );
        assert_eq!(
            serde_json::to_string(&IntentStatus::PolicyChecked).unwrap(),
            "\"policy_checked\""
        );
        assert_eq!(serde_json::to_string(&RiskLevel::L3).unwrap(), "\"l3\"");
        assert_eq!(
            serde_json::to_string(&IntentAction::MassRecall).unwrap(),
            "\"mass_recall\""
        );
        for status in IntentStatus::ALL {
            let back: IntentStatus =
                serde_json::from_str(&serde_json::to_string(&status).unwrap()).unwrap();
            assert_eq!(back, status);
            assert_eq!(status.as_str(), status.to_string());
        }
        for risk in [RiskLevel::L1, RiskLevel::L2, RiskLevel::L3, RiskLevel::L4] {
            let back: RiskLevel =
                serde_json::from_str(&serde_json::to_string(&risk).unwrap()).unwrap();
            assert_eq!(back, risk);
        }
        for action in IntentAction::ALL {
            let back: IntentAction =
                serde_json::from_str(&serde_json::to_string(&action).unwrap()).unwrap();
            assert_eq!(back, action);
        }
        assert!(serde_json::from_str::<IntentStatus>("\"ProofRequired\"").is_err());
        assert!(serde_json::from_str::<IntentStatus>("\"unknown\"").is_err());
        assert!(serde_json::from_str::<RiskLevel>("\"L3\"").is_err());
        assert!(serde_json::from_str::<IntentAction>("\"freeze\"").is_err());
    }
}
