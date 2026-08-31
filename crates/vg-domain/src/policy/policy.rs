//! 策略：辖区级监管策略与迁移前策略引擎裁决。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::credential::{CredentialType, VerifiableCredential};
use crate::lifecycle::LifecycleState;
use crate::shared::{Did, DomainError, PolicyId, ProofId};

/// 策略要求出示的证明种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    /// 权属证明。
    Ownership,
    /// 冷链证明。
    ColdChain,
    /// 区间约束证明（如温度/数量区间）。
    Range,
    /// 时间年龄证明（如酒类窖藏年限）。
    Age,
    /// 身份证明。
    Identity,
    /// 凭证持有证明（ZK 匿证持有某 VC）。
    Credential,
}

impl ProofKind {
    /// snake_case 名称，与 serde 序列化结果一致。
    pub fn as_str(&self) -> &'static str {
        match self {
            ProofKind::Ownership => "ownership",
            ProofKind::ColdChain => "cold_chain",
            ProofKind::Range => "range",
            ProofKind::Age => "age",
            ProofKind::Identity => "identity",
            ProofKind::Credential => "credential",
        }
    }
}

impl std::fmt::Display for ProofKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 已验证证明的引用：引擎不接收证明本体，只接收"某证明已通过验证"的结论。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedProofRef {
    /// 证明标识符。
    pub proof_id: ProofId,
    /// 证明种类。
    pub kind: ProofKind,
    /// 是否通过验证；引擎只认 `verified == true`。
    pub verified: bool,
}

/// 策略版本号口径：`(policy_id, version)`，供 lifecycle_event.policy_version 引用。
pub type PolicyVersion = (PolicyId, u64);

/// 策略裁决结果：记录本次迁移实际执行的策略版本集合。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// 生效执行的策略版本列表（每条被检核通过的适用策略一条）。
    pub enforced: Vec<PolicyVersion>,
}

/// 辖区级监管策略：声明某类商品在指定迁移上必须满足的凭证与证明约束。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// 策略标识符。
    pub policy_id: PolicyId,
    /// 版本号（同一 policy_id 下单调递增）。
    pub version: u64,
    /// 签发策略的监管机构 DID。
    pub authority: Did,
    /// 适用辖区。
    pub jurisdiction: String,
    /// 适用商品类型。
    pub product_type: String,
    /// 必需凭证类型集合。
    pub required_credentials: Vec<CredentialType>,
    /// 必需证明种类集合。
    pub required_proofs: Vec<ProofKind>,
    /// 约束的生命周期迁移集合（from → to 二元组）。
    pub transitions: Vec<(LifecycleState, LifecycleState)>,
    /// 生效时刻。
    pub effective_at: DateTime<Utc>,
    /// 失效时刻；`None` 表示长期有效。
    pub expires_at: Option<DateTime<Utc>>,
    /// 启用标志（运营开关，独立于时间窗口）。
    pub active: bool,
}

impl Policy {
    /// 策略在 `now` 时刻是否生效：启用且处于 `[effective_at, expires_at)` 窗口内。
    ///
    /// 过期边界与全库口径一致：`now >= expires_at` 即失效。
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        if !self.active {
            return false;
        }
        if now < self.effective_at {
            return false;
        }
        match self.expires_at {
            Some(expires_at) => now < expires_at,
            None => true,
        }
    }

    /// 策略是否约束指定迁移（不判断生效窗口，由调用方用 [`Policy::is_active`] 组合）。
    pub fn allows_transition(&self, from: LifecycleState, to: LifecycleState) -> bool {
        self.transitions.iter().any(|&(f, t)| f == from && t == to)
    }
}

/// 策略引擎：纯函数域服务（unit struct，无状态）。
///
/// 所有裁决只依赖入参，便于确定性测试与上层直接复用。
pub struct PolicyEngine;

impl PolicyEngine {
    /// 迁移前策略检核：对每条适用策略（生效且约束该迁移）逐一核验凭证与证明。
    ///
    /// 语义：
    /// - 适用策略为空 → `Ok`（默认放行：策略是叠加约束，而非白名单）；
    /// - 多条适用策略需**全部满足**（每条监管约束都要成立）；
    /// - `required_credentials`：每个类型在 `creds` 中存在 `ctype` 匹配且
    ///   `is_effective(now)` 的 VC，缺 → [`DomainError::PolicyViolated`]；
    /// - `required_proofs`：每个种类在 `proofs` 中存在 `kind` 匹配且
    ///   `verified == true` 的引用，缺 → [`DomainError::PolicyViolated`]；
    /// - 成功时 `enforced` 记录全部被执行的策略版本。
    pub fn check_transition(
        policies: &[Policy],
        creds: &[VerifiableCredential],
        proofs: &[VerifiedProofRef],
        from: LifecycleState,
        to: LifecycleState,
        now: DateTime<Utc>,
    ) -> Result<PolicyDecision, DomainError> {
        let applicable: Vec<&Policy> = policies
            .iter()
            .filter(|p| p.is_active(now) && p.allows_transition(from, to))
            .collect();
        if applicable.is_empty() {
            // 无适用策略：默认放行（"policy 过期不生效"依赖此语义）。
            return Ok(PolicyDecision { enforced: vec![] });
        }

        for policy in &applicable {
            Self::enforce_policy(policy, creds, proofs, now)?;
        }
        Ok(PolicyDecision {
            enforced: applicable
                .iter()
                .map(|p| (p.policy_id.clone(), p.version))
                .collect(),
        })
    }

    /// 核验单条策略的凭证与证明要求；违规即返回带明细的 [`DomainError::PolicyViolated`]。
    fn enforce_policy(
        policy: &Policy,
        creds: &[VerifiableCredential],
        proofs: &[VerifiedProofRef],
        now: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        let missing_creds: Vec<&str> = policy
            .required_credentials
            .iter()
            .filter(|ctype| {
                !creds
                    .iter()
                    .any(|vc| vc.ctype == **ctype && vc.is_effective(now))
            })
            .map(|ctype| ctype.as_str())
            .collect();
        if !missing_creds.is_empty() {
            return Err(DomainError::PolicyViolated(format!(
                "策略 {}@v{} 缺少有效凭证：{}",
                policy.policy_id,
                policy.version,
                missing_creds.join("、")
            )));
        }

        let missing_proofs: Vec<&str> = policy
            .required_proofs
            .iter()
            .filter(|kind| {
                !proofs
                    .iter()
                    .any(|p| p.kind == **kind && p.verified)
            })
            .map(|kind| kind.as_str())
            .collect();
        if !missing_proofs.is_empty() {
            return Err(DomainError::PolicyViolated(format!(
                "策略 {}@v{} 缺少已验证证明：{}",
                policy.policy_id,
                policy.version,
                missing_proofs.join("、")
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(month: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, month, 1, 0, 0, 0).unwrap()
    }

    fn sample_policy() -> Policy {
        Policy {
            policy_id: PolicyId::new("pol-export"),
            version: 3,
            authority: Did::parse("did:vg:user:reg-001").unwrap(),
            jurisdiction: "CN".into(),
            product_type: "food".into(),
            required_credentials: vec![CredentialType::Customs, CredentialType::Tax],
            required_proofs: vec![ProofKind::ColdChain],
            transitions: vec![(LifecycleState::InWarehouse, LifecycleState::InTransit)],
            effective_at: t(1),
            expires_at: Some(t(12)),
            active: true,
        }
    }

    fn sample_cred(ctype: CredentialType, expires_at: Option<DateTime<Utc>>) -> VerifiableCredential {
        VerifiableCredential::new(
            crate::shared::CredentialId::generate(),
            Did::parse("did:vg:user:reg-001").unwrap(),
            Did::parse("did:vg:user:ent-100").unwrap(),
            ctype,
            serde_json::json!({"k": "v"}),
            t(1),
            expires_at,
        )
        .expect("样例凭证应构造成功")
    }

    // ---- is_active ----

    #[test]
    fn is_active_covers_window_before_and_expired() {
        let policy = sample_policy();
        // 生效窗口内
        assert!(policy.is_active(t(6)));
        // 边界：effective_at 当刻生效
        assert!(policy.is_active(t(1)));
        // 未到 effective_at
        assert!(!policy.is_active(Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap()));
        // 已过期：now >= expires_at 即失效（含边界当刻）
        assert!(!policy.is_active(t(12)), "now == expires_at 应已失效");
        // 运营开关关闭：即使在窗口内也不生效
        let mut off = sample_policy();
        off.active = false;
        assert!(!off.is_active(t(6)));
    }

    #[test]
    fn is_active_with_no_expiry_is_open_ended() {
        let mut policy = sample_policy();
        policy.expires_at = None;
        assert!(policy.is_active(t(6)));
        assert!(policy.is_active(Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap()));
    }

    // ---- allows_transition ----

    #[test]
    fn allows_transition_hits_and_misses() {
        let policy = sample_policy();
        assert!(policy.allows_transition(
            LifecycleState::InWarehouse,
            LifecycleState::InTransit
        ));
        assert!(!policy.allows_transition(
            LifecycleState::InWarehouse,
            LifecycleState::Sold
        ));
        assert!(!policy.allows_transition(
            LifecycleState::Created,
            LifecycleState::InTransit
        ));
    }

    // ---- serde ----

    #[test]
    fn proof_kind_and_policy_serialize() {
        assert_eq!(
            serde_json::to_string(&ProofKind::ColdChain).unwrap(),
            "\"cold_chain\""
        );
        // transitions 元组序列化为二元数组
        let policy = sample_policy();
        let value = serde_json::to_value(&policy).expect("序列化应成功");
        assert_eq!(
            value["transitions"],
            serde_json::json!([["in_warehouse", "in_transit"]])
        );
        let back: Policy = serde_json::from_value(value).expect("反序列化应成功");
        assert_eq!(back, policy);
    }

    // ---- check_transition ----

    #[test]
    fn check_transition_allows_when_no_applicable_policy() {
        // 空策略集：默认放行
        let decision = PolicyEngine::check_transition(
            &[],
            &[],
            &[],
            LifecycleState::Created,
            LifecycleState::Produced,
            t(6),
        )
        .expect("无策略应放行");
        assert!(decision.enforced.is_empty());

        // 有策略但不约束该迁移：同样放行
        let decision = PolicyEngine::check_transition(
            &[sample_policy()],
            &[],
            &[],
            LifecycleState::Created,
            LifecycleState::Produced,
            t(6),
        )
        .expect("不约束该迁移应放行");
        assert!(decision.enforced.is_empty());
    }

    #[test]
    fn expired_policy_does_not_apply() {
        let policy = sample_policy(); // expires_at = 12 月
        let decision = PolicyEngine::check_transition(
            &[policy],
            &[], // 无任何凭证——若策略生效应被拒绝
            &[],
            LifecycleState::InWarehouse,
            LifecycleState::InTransit,
            t(12), // now >= expires_at：策略已过期
        )
        .expect("过期策略不生效，应放行");
        assert!(decision.enforced.is_empty());
    }

    #[test]
    fn missing_required_credential_is_rejected_with_detail() {
        let err = PolicyEngine::check_transition(
            &[sample_policy()],
            &[sample_cred(CredentialType::Customs, None)], // 缺 Tax
            &[proof(ProofKind::ColdChain)],
            LifecycleState::InWarehouse,
            LifecycleState::InTransit,
            t(6),
        )
        .expect_err("缺少必需凭证必须拒绝");
        let DomainError::PolicyViolated(msg) = &err else {
            panic!("应为 PolicyViolated，实际：{err:?}");
        };
        assert!(msg.contains("tax"), "消息应含缺失类型名：{msg}");
        assert!(msg.contains("pol-export"), "消息应含策略 id：{msg}");
        assert!(msg.contains('3'), "消息应含版本号：{msg}");
    }

    #[test]
    fn ineffective_credential_does_not_count() {
        // 类型匹配但状态被吊销
        let mut revoked = sample_cred(CredentialType::Customs, None);
        revoked.status = crate::credential::CredStatus::Revoked;
        let err = PolicyEngine::check_transition(
            &[{
                let mut p = sample_policy();
                p.required_credentials = vec![CredentialType::Customs];
                p
            }],
            &[revoked],
            &[],
            LifecycleState::InWarehouse,
            LifecycleState::InTransit,
            t(6),
        )
        .expect_err("状态无效的凭证不算数");
        assert!(matches!(err, DomainError::PolicyViolated(_)));

        // 类型匹配但已过期（now >= vc.expires_at）
        let expired = sample_cred(CredentialType::Customs, Some(t(3)));
        let err = PolicyEngine::check_transition(
            &[{
                let mut p = sample_policy();
                p.required_credentials = vec![CredentialType::Customs];
                p
            }],
            &[expired],
            &[],
            LifecycleState::InWarehouse,
            LifecycleState::InTransit,
            t(6),
        )
        .expect_err("过期凭证不算数");
        assert!(matches!(err, DomainError::PolicyViolated(_)));
    }

    fn proof(kind: ProofKind) -> VerifiedProofRef {
        VerifiedProofRef {
            proof_id: ProofId::generate(),
            kind,
            verified: true,
        }
    }

    #[test]
    fn missing_or_unverified_proof_is_rejected() {
        let mut policy = sample_policy();
        policy.required_credentials = vec![]; // 单独考察证明维度

        // 完全缺失
        let err = PolicyEngine::check_transition(
            &[policy.clone()],
            &[],
            &[],
            LifecycleState::InWarehouse,
            LifecycleState::InTransit,
            t(6),
        )
        .expect_err("缺少必需证明必须拒绝");
        let DomainError::PolicyViolated(msg) = &err else {
            panic!("应为 PolicyViolated，实际：{err:?}");
        };
        assert!(msg.contains("cold_chain"), "消息应含证明类型名：{msg}");

        // 存在但 verified=false：不算数
        let mut unverified = proof(ProofKind::ColdChain);
        unverified.verified = false;
        let err = PolicyEngine::check_transition(
            &[policy],
            &[],
            &[unverified],
            LifecycleState::InWarehouse,
            LifecycleState::InTransit,
            t(6),
        )
        .expect_err("verified=false 的证明不算数");
        assert!(matches!(err, DomainError::PolicyViolated(_)));
    }

    #[test]
    fn all_applicable_policies_must_pass() {
        // pol-a：Customs；pol-b：Tax —— 只满足 pol-a 应整体拒绝
        let mut pol_a = sample_policy();
        pol_a.policy_id = PolicyId::new("pol-a");
        pol_a.required_credentials = vec![CredentialType::Customs];
        pol_a.required_proofs = vec![];
        let mut pol_b = sample_policy();
        pol_b.policy_id = PolicyId::new("pol-b");
        pol_b.required_credentials = vec![CredentialType::Tax];
        pol_b.required_proofs = vec![];

        let err = PolicyEngine::check_transition(
            &[pol_a.clone(), pol_b],
            &[sample_cred(CredentialType::Customs, None)],
            &[],
            LifecycleState::InWarehouse,
            LifecycleState::InTransit,
            t(6),
        )
        .expect_err("部分满足应拒绝");
        let DomainError::PolicyViolated(msg) = &err else {
            panic!("应为 PolicyViolated，实际：{err:?}");
        };
        assert!(msg.contains("pol-b"), "应指明未满足的策略：{msg}");

        // 两条全部满足 → 通过，enforced 记录两个版本
        let mut pol_b = sample_policy();
        pol_b.policy_id = PolicyId::new("pol-b");
        pol_b.required_credentials = vec![CredentialType::Tax];
        pol_b.required_proofs = vec![];
        let decision = PolicyEngine::check_transition(
            &[pol_a, pol_b],
            &[
                sample_cred(CredentialType::Customs, None),
                sample_cred(CredentialType::Tax, None),
            ],
            &[],
            LifecycleState::InWarehouse,
            LifecycleState::InTransit,
            t(6),
        )
        .expect("全部满足应通过");
        assert_eq!(
            decision.enforced,
            vec![(PolicyId::new("pol-a"), 3), (PolicyId::new("pol-b"), 3)]
        );
    }

    #[test]
    fn full_compliance_passes_and_records_enforced_versions() {
        let decision = PolicyEngine::check_transition(
            &[sample_policy()],
            &[
                sample_cred(CredentialType::Customs, None),
                sample_cred(CredentialType::Tax, None),
            ],
            &[proof(ProofKind::ColdChain)],
            LifecycleState::InWarehouse,
            LifecycleState::InTransit,
            t(6),
        )
        .expect("全部满足应通过");
        assert_eq!(decision.enforced, vec![(PolicyId::new("pol-export"), 3)]);

        // serde 往返：enforced 元组数组可序列化
        let back: PolicyDecision =
            serde_json::from_str(&serde_json::to_string(&decision).unwrap()).unwrap();
        assert_eq!(back, decision);
    }
}
