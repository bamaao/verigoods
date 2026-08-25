//! 身份上下文：DID 文档与验证方法。
//!
//! 每个主体（企业、消费者、监管方等）持有一份 [`DidDocument`]，
//! 内含若干 [`VerificationMethod`]；智能体（Agent）文档必须通过 `parent`
//! 挂靠到一个非智能体主体，且禁止嵌套委托。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::shared::{Did, DomainError, Hash32};

/// 主体类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// 企业（商品发行与批次创建主体）。
    Enterprise,
    /// 消费者。
    Consumer,
    /// 监管方。
    Regulator,
    /// 核验/稽查人员。
    Inspector,
    /// 物流承运方。
    Logistics,
    /// 智能体（受企业委托执行操作的代理 DID）。
    Agent,
    /// 设备（如冷链传感器）。
    Device,
}

/// 密钥算法类型。当前仅支持 secp256k1。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// secp256k1（与链上签名方案一致）。
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

/// 验证方法：一条可验证的公钥绑定记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// 方法标识符（DID 文档内唯一）。
    pub id: String,
    /// 密钥算法类型。
    pub key_type: KeyType,
    /// 公钥摘要。
    pub public_key: Hash32,
    /// 控制该方法的主体 DID。
    pub controller: Did,
    /// 是否已撤销。
    pub revoked: bool,
}

impl VerificationMethod {
    /// 由公钥摘要构造未撤销的验证方法。
    pub fn new(
        id: impl Into<String>,
        key_type: KeyType,
        public_key: Hash32,
        controller: Did,
    ) -> Self {
        Self {
            id: id.into(),
            key_type,
            public_key,
            controller,
            revoked: false,
        }
    }
}

/// DID 文档：主体的身份声明与密钥集合。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    /// 主体 DID。
    pub did: Did,
    /// 主体类型。
    pub kind: SubjectKind,
    /// 验证方法列表（可为空，此时无法发起任何签名操作）。
    pub methods: Vec<VerificationMethod>,
    /// 父主体（仅 Agent 类型允许且必须存在）。
    pub parent: Option<Did>,
    /// 司法辖区（可选）。
    pub jurisdiction: Option<String>,
    /// 创建时间（UTC）。
    pub created_at: DateTime<Utc>,
}

impl DidDocument {
    /// 首个未撤销的验证方法；不存在时返回 `None`。
    pub fn active_pubkey(&self) -> Option<&VerificationMethod> {
        self.methods.iter().find(|m| !m.revoked)
    }

    /// 校验文档结构约束：
    /// 1. `kind == Agent` 时必须存在父主体，且父主体不得再是智能体；
    /// 2. 非 Agent 主体不得设置父主体。
    ///
    /// 违规一律返回 [`DomainError::Unauthorized`] 并携带中文原因。
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.kind == SubjectKind::Agent {
            let parent = self.parent.as_ref().ok_or_else(|| {
                DomainError::Unauthorized("智能体文档缺少父主体，须挂靠到非智能体主体".into())
            })?;
            if parent.is_agent() {
                return Err(DomainError::Unauthorized(
                    "智能体的父主体不得再是智能体（禁止嵌套委托）".into(),
                ));
            }
        } else if self.parent.is_some() {
            return Err(DomainError::Unauthorized(
                "非智能体主体不得设置父主体".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// 固定时间戳，避免测试依赖真实时钟。
    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn enterprise_did() -> Did {
        Did::parse("did:vg:user:ent-001").unwrap()
    }

    fn agent_did() -> Did {
        Did::parse("did:vg:agent:ag-001").unwrap()
    }

    /// 构造最小可用文档。
    fn doc(did: Did, kind: SubjectKind, parent: Option<Did>) -> DidDocument {
        DidDocument {
            did,
            kind,
            methods: Vec::new(),
            parent,
            jurisdiction: None,
            created_at: fixed_time(),
        }
    }

    // ---- validate 规则 ----

    #[test]
    fn agent_without_parent_is_rejected() {
        let d = doc(agent_did(), SubjectKind::Agent, None);
        let err = d.validate().expect_err("缺 parent 的智能体文档应被拒绝");
        assert!(
            matches!(err, DomainError::Unauthorized(_)),
            "实际错误：{err:?}"
        );
    }

    #[test]
    fn agent_with_agent_parent_is_rejected() {
        // 父主体本身是智能体 → 禁止嵌套委托
        let d = doc(agent_did(), SubjectKind::Agent, Some(agent_did()));
        let err = d.validate().expect_err("父主体为智能体应被拒绝");
        assert!(
            matches!(err, DomainError::Unauthorized(_)),
            "实际错误：{err:?}"
        );
    }

    #[test]
    fn non_agent_with_parent_is_rejected() {
        let d = doc(enterprise_did(), SubjectKind::Enterprise, Some(agent_did()));
        let err = d.validate().expect_err("非智能体带 parent 应被拒绝");
        assert!(
            matches!(err, DomainError::Unauthorized(_)),
            "实际错误：{err:?}"
        );
    }

    #[test]
    fn valid_enterprise_and_agent_documents_pass() {
        // 合法企业：无 parent
        let enterprise = doc(enterprise_did(), SubjectKind::Enterprise, None);
        enterprise.validate().expect("合法企业文档应通过校验");

        // 合法智能体：parent 为非智能体主体
        let agent = doc(agent_did(), SubjectKind::Agent, Some(enterprise_did()));
        agent.validate().expect("合法智能体文档应通过校验");
    }

    #[test]
    fn all_subject_kinds_follow_parent_rule() {
        for kind in [
            SubjectKind::Consumer,
            SubjectKind::Regulator,
            SubjectKind::Inspector,
            SubjectKind::Logistics,
            SubjectKind::Device,
        ] {
            let with_parent = doc(
                Did::parse("did:vg:user:x").unwrap(),
                kind,
                Some(enterprise_did()),
            );
            let err = with_parent
                .validate()
                .expect_err("非智能体带 parent 一律拒绝");
            assert!(matches!(err, DomainError::Unauthorized(_)));

            let without_parent = doc(Did::parse("did:vg:user:y").unwrap(), kind, None);
            without_parent.validate().expect("非智能体无 parent 应通过");
        }
    }

    // ---- active_pubkey ----

    #[test]
    fn active_pubkey_empty_methods_returns_none() {
        let d = doc(enterprise_did(), SubjectKind::Enterprise, None);
        assert!(d.active_pubkey().is_none());
    }

    #[test]
    fn active_pubkey_all_revoked_returns_none() {
        let mut d = doc(enterprise_did(), SubjectKind::Enterprise, None);
        d.methods.push(VerificationMethod {
            id: "k1".into(),
            key_type: KeyType::Secp256k1,
            public_key: Hash32::keccak(b"key-1"),
            controller: d.did.clone(),
            revoked: true,
        });
        assert!(d.active_pubkey().is_none(), "全部撤销时应返回 None");
    }

    #[test]
    fn active_pubkey_takes_first_active_method() {
        let mut d = doc(enterprise_did(), SubjectKind::Enterprise, None);
        let revoked = VerificationMethod::new(
            "revoked-key",
            KeyType::Secp256k1,
            Hash32::keccak(b"old"),
            d.did.clone(),
        );
        let active = VerificationMethod::new(
            "active-key",
            KeyType::Secp256k1,
            Hash32::keccak(b"current"),
            d.did.clone(),
        );
        // 首个已撤销 + 第二个活跃 → 取首个活跃
        let mut first = revoked;
        first.revoked = true;
        d.methods.push(first);
        d.methods.push(active);

        let found = d.active_pubkey().expect("存在活跃方法应返回 Some");
        assert_eq!(found.id, "active-key");
        assert_eq!(found.public_key, Hash32::keccak(b"current"));
        assert!(!found.revoked);
    }

    // ---- serde ----

    #[test]
    fn subject_kind_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&SubjectKind::Consumer).unwrap(),
            "\"consumer\""
        );
        assert_eq!(
            serde_json::to_string(&SubjectKind::Agent).unwrap(),
            "\"agent\""
        );

        // 反序列化：snake_case 字符串还原为对应变体，未知值被拒绝
        let back: SubjectKind = serde_json::from_str("\"logistics\"").expect("应可反序列化");
        assert_eq!(back, SubjectKind::Logistics);
        assert!(
            serde_json::from_str::<SubjectKind>("\"Enterprise\"").is_err(),
            "非 snake_case 输入必须被拒绝"
        );
    }

    #[test]
    fn key_type_serializes_as_secp256k1() {
        assert_eq!(
            serde_json::to_string(&KeyType::Secp256k1).unwrap(),
            "\"secp256k1\""
        );
        let back: KeyType = serde_json::from_str("\"secp256k1\"").unwrap();
        assert_eq!(back, KeyType::Secp256k1);
    }

    #[test]
    fn document_json_roundtrip() {
        let mut d = doc(agent_did(), SubjectKind::Agent, Some(enterprise_did()));
        d.jurisdiction = Some("CN".into());
        d.methods.push(VerificationMethod::new(
            "k-1",
            KeyType::Secp256k1,
            Hash32::keccak(b"pk"),
            d.did.clone(),
        ));

        let json = serde_json::to_string(&d).expect("序列化应成功");
        let back: DidDocument = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(back, d);
    }
}
