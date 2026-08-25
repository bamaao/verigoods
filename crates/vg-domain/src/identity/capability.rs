//! 身份上下文：能力委托（Capability）。
//!
//! 企业等主体通过 [`Capability`] 把特定操作委托给智能体；
//! [`assert_allowed`] 在执行动作前校验能力是否存在且未过期。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use crate::shared::{Did, DomainError};

/// 可被委托的动作集合。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// 读取商品。
    ReadProduct,
    /// 创建批次。
    CreateBatch,
    /// 发起转移请求。
    RequestTransfer,
    /// 转移所有权。
    TransferOwnership,
    /// 签发凭证。
    IssueCredential,
    /// 撤销凭证。
    RevokeCredential,
    /// 注册策略。
    RegisterPolicy,
    /// 更新保管（物流节点）。
    UpdateCustody,
    /// 提交隐形交易。
    SubmitShieldedTx,
    /// 大规模召回。
    MassRecall,
}

impl Action {
    /// snake_case 名称，与 serde 序列化结果一致。
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::ReadProduct => "read_product",
            Action::CreateBatch => "create_batch",
            Action::RequestTransfer => "request_transfer",
            Action::TransferOwnership => "transfer_ownership",
            Action::IssueCredential => "issue_credential",
            Action::RevokeCredential => "revoke_credential",
            Action::RegisterPolicy => "register_policy",
            Action::UpdateCustody => "update_custody",
            Action::SubmitShieldedTx => "submit_shielded_tx",
            Action::MassRecall => "mass_recall",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 一条能力委托：`granted_by` 授权 `agent` 执行 `action`，可选过期时间。
///
/// 字段私有：构造与反序列化都必须经由 [`Capability::new`]，
/// "授权方不得是智能体"约束因此无法被任何输入路径绕过
/// （与 [`crate::shared::Did`] 的手写校验型反序列化同一先例）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capability {
    /// 被授权执行操作的智能体 DID。
    agent: Did,
    /// 被委托的动作。
    action: Action,
    /// 授权方 DID（必须为非智能体主体）。
    granted_by: Did,
    /// 过期时间；`None` 表示长期有效。
    expires_at: Option<DateTime<Utc>>,
}

impl Capability {
    /// 构造能力委托。
    ///
    /// 约束：授权方不得是智能体（禁止智能体二次转授），
    /// 违规返回 [`DomainError::Unauthorized`]。
    pub fn new(
        agent: Did,
        action: Action,
        granted_by: Did,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Self, DomainError> {
        if granted_by.is_agent() {
            return Err(DomainError::Unauthorized(
                "授权方不得是智能体（智能体无权转授能力）".into(),
            ));
        }
        Ok(Self {
            agent,
            action,
            granted_by,
            expires_at,
        })
    }

    /// 被授权的智能体 DID。
    pub fn agent(&self) -> &Did {
        &self.agent
    }

    /// 被委托的动作。
    pub fn action(&self) -> &Action {
        &self.action
    }

    /// 授权方 DID。
    pub fn granted_by(&self) -> &Did {
        &self.granted_by
    }

    /// 过期时间（若有）。
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    /// 是否在 `now` 时刻仍然有效（未过期）。
    ///
    /// 无过期时间视为长期有效；到达过期时刻即失效（`now >= expires_at` 为过期）。
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            Some(expires_at) => now < expires_at,
            None => true,
        }
    }
}

/// 反序列化中间载体：仅用于捕获原始字段，随后强制走 [`Capability::new`] 校验。
#[derive(Deserialize)]
struct RawCapability {
    agent: Did,
    action: Action,
    granted_by: Did,
    expires_at: Option<DateTime<Utc>>,
}

impl<'de> Deserialize<'de> for Capability {
    /// 手写实现：先还原字段，再委托 [`Capability::new`] 做授权方校验，
    /// 使 `"granted_by": "did:vg:agent:..."` 这类非法输入报 serde 数据错误，
    /// 而非绕过领域规则静默构造。
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawCapability::deserialize(deserializer)?;
        Capability::new(raw.agent, raw.action, raw.granted_by, raw.expires_at)
            .map_err(serde::de::Error::custom)
    }
}

/// 断言能力列表中存在允许执行 `action` 的有效条目。
///
/// 无匹配动作或全部已过期时返回 [`DomainError::Unauthorized`] 并携带中文原因。
pub fn assert_allowed(
    caps: &[Capability],
    action: &Action,
    now: DateTime<Utc>,
) -> Result<(), DomainError> {
    let allowed = caps
        .iter()
        .any(|cap| cap.action == *action && cap.is_active_at(now));
    if allowed {
        Ok(())
    } else {
        Err(DomainError::Unauthorized(format!(
            "缺少执行 `{action}` 的有效能力授权"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn enterprise() -> Did {
        Did::parse("did:vg:user:ent-001").unwrap()
    }

    fn agent() -> Did {
        Did::parse("did:vg:agent:ag-001").unwrap()
    }

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    // ---- Capability::new ----

    #[test]
    fn new_with_agent_grantor_is_rejected() {
        let err = Capability::new(
            agent(),
            Action::ReadProduct,
            agent(), // 授权方是智能体 → 非法
            None,
        )
        .expect_err("授权方为智能体应被拒绝");
        assert!(
            matches!(err, DomainError::Unauthorized(_)),
            "实际错误：{err:?}"
        );
    }

    #[test]
    fn new_with_enterprise_grantor_succeeds_and_keeps_fields_private() {
        let cap = Capability::new(agent(), Action::CreateBatch, enterprise(), None)
            .expect("企业授权应成功");
        assert_eq!(cap.agent(), &agent());
        assert_eq!(cap.action(), &Action::CreateBatch);
        assert_eq!(cap.granted_by(), &enterprise());
        assert_eq!(cap.expires_at(), None);
    }

    #[test]
    fn is_active_respects_expiry_boundary() {
        let at = fixed_time();
        let expired = Some(at);
        let future = Some(at + chrono::Duration::hours(1));

        let long_lived =
            Capability::new(agent(), Action::IssueCredential, enterprise(), None).unwrap();
        let dead =
            Capability::new(agent(), Action::IssueCredential, enterprise(), expired).unwrap();
        let alive =
            Capability::new(agent(), Action::IssueCredential, enterprise(), future).unwrap();

        assert!(long_lived.is_active_at(at), "无过期时间应长期有效");
        assert!(!dead.is_active_at(at), "到达过期时刻即视为失效");
        assert!(alive.is_active_at(at), "未到期应有效");
    }

    // ---- assert_allowed ----

    #[test]
    fn empty_capability_list_is_rejected() {
        let err = assert_allowed(&[], &Action::ReadProduct, fixed_time())
            .expect_err("空能力列表必须拒绝");
        assert!(
            matches!(err, DomainError::Unauthorized(_)),
            "实际错误：{err:?}"
        );
    }

    #[test]
    fn mismatched_action_is_rejected() {
        let caps = vec![Capability::new(agent(), Action::CreateBatch, enterprise(), None).unwrap()];
        let err = assert_allowed(&caps, &Action::MassRecall, fixed_time())
            .expect_err("动作不匹配必须拒绝");
        assert!(matches!(err, DomainError::Unauthorized(_)));
    }

    #[test]
    fn expired_capability_is_rejected() {
        let at = fixed_time();
        let caps = vec![Capability::new(
            agent(),
            Action::TransferOwnership,
            enterprise(),
            Some(at - chrono::Duration::seconds(1)),
        )
        .unwrap()];
        let err =
            assert_allowed(&caps, &Action::TransferOwnership, at).expect_err("已过期能力必须拒绝");
        assert!(matches!(err, DomainError::Unauthorized(_)));
    }

    #[test]
    fn matching_unexpired_capability_passes() {
        let at = fixed_time();
        let caps = vec![
            Capability::new(agent(), Action::UpdateCustody, enterprise(), Some(at)).unwrap(),
            Capability::new(
                agent(),
                Action::SubmitShieldedTx,
                enterprise(),
                Some(at + chrono::Duration::days(7)),
            )
            .unwrap(),
        ];
        // 第一条恰好在当前时刻过期 → 由第二条兜底通过
        assert_allowed(&caps, &Action::SubmitShieldedTx, at).expect("有效能力应放行");
        // 无过期时间的长期授权也应放行
        let caps = vec![Capability::new(agent(), Action::ReadProduct, enterprise(), None).unwrap()];
        assert_allowed(&caps, &Action::ReadProduct, at).expect("长期授权应放行");
    }

    // ---- serde ----

    #[test]
    fn action_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&Action::RequestTransfer).unwrap(),
            "\"request_transfer\""
        );
        assert_eq!(
            serde_json::to_string(&Action::SubmitShieldedTx).unwrap(),
            "\"submit_shielded_tx\""
        );
        assert_eq!(
            serde_json::to_string(&Action::MassRecall).unwrap(),
            "\"mass_recall\""
        );

        let back: Action = serde_json::from_str("\"issue_credential\"").expect("应可反序列化");
        assert_eq!(back, Action::IssueCredential);
    }

    #[test]
    fn capability_json_roundtrip() {
        let at = fixed_time();
        let cap = Capability::new(
            agent(),
            Action::RegisterPolicy,
            enterprise(),
            Some(at + chrono::Duration::days(30)),
        )
        .unwrap();

        let json = serde_json::to_string(&cap).expect("序列化应成功");
        assert!(
            json.contains("\"action\":\"register_policy\""),
            "实际 JSON：{json}"
        );

        let back: Capability = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(back, cap);
    }

    #[test]
    fn deserialization_rejects_agent_grantor_json() {
        // 回归测试：派生 Deserialize 会直接构造私有字段、绕过 Capability::new
        // 的授权方校验，使智能体转授的 JSON 静默通过。反序列化必须强制走
        // new()，非法 granted_by 报 serde 数据错误。
        let json = format!(
            r#"{{"agent":"{}","action":"read_product","granted_by":"did:vg:agent:rogue-agent","expires_at":null}}"#,
            agent()
        );
        let err = serde_json::from_str::<Capability>(&json)
            .expect_err("granted_by 为智能体的 JSON 必须被拒绝");
        assert!(err.is_data(), "应为 serde 数据错误：{err}");
        assert!(
            err.to_string().contains("授权方"),
            "错误应携带 new() 的中文校验原因：{err}"
        );
    }

    #[test]
    fn deserialization_of_valid_capability_succeeds() {
        // 不依赖序列化输出的独立合法用例：字段齐全且 granted_by 非 agent
        let json = format!(
            r#"{{"agent":"{}","action":"create_batch","granted_by":"{}","expires_at":null}}"#,
            agent(),
            enterprise()
        );
        let cap: Capability = serde_json::from_str(&json).expect("合法 JSON 应可反序列化");
        assert_eq!(cap.agent(), &agent());
        assert_eq!(cap.action(), &Action::CreateBatch);
        assert_eq!(cap.granted_by(), &enterprise());
        assert_eq!(cap.expires_at(), None);
    }

    #[test]
    fn action_display_matches_serde_name() {
        for action in [
            Action::ReadProduct,
            Action::CreateBatch,
            Action::RequestTransfer,
            Action::TransferOwnership,
            Action::IssueCredential,
            Action::RevokeCredential,
            Action::RegisterPolicy,
            Action::UpdateCustody,
            Action::SubmitShieldedTx,
            Action::MassRecall,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let expected = format!("\"{}\"", action.as_str());
            assert_eq!(json, expected, "Display/as_str 应与 serde 命名一致");
        }
    }
}
