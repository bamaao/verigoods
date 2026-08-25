//! 可验证凭证（Verifiable Credential, VC）聚合。
//!
//! - [`CredentialType`]：12 类业务凭证类型（serde 小写蛇形）；
//! - [`VerifiableCredential`]：VC 聚合根，含内容哈希承诺与签发方驱动的状态机；
//! - [`CredentialSchema`]：凭证模板，约束某类凭证必须携带的 claims 键。
//!
//! 哈希承诺：`credential_hash = keccak256(规范化 JSON)`，其中 status 与
//! credential_hash 本身**不参与**哈希——前者随状态机独立演进，后者是哈希自身
//! （否则循环定义），因此状态迁移无需重算内容哈希，链上锚定值保持稳定。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};

use crate::shared::{CredentialId, Did, DomainError, Hash32};

use super::status::CredStatus;

/// 凭证类型（12 类全量）。
///
/// serde 序列化为小写蛇形，如 [`CredentialType::FoodSafetyInspection`]
/// → `"food_safety_inspection"`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// 营业执照。
    EnterpriseLicense,
    /// 生产许可证。
    ProductionLicense,
    /// 产地证明。
    Origin,
    /// 食品安全检测。
    FoodSafetyInspection,
    /// 质量检验。
    QualityInspection,
    /// 冷链认证。
    ColdChain,
    /// 报关单证。
    Customs,
    /// 完税证明。
    Tax,
    /// 真伪鉴定。
    Authenticity,
    /// 权属证明。
    Ownership,
    /// 运输凭证。
    Transport,
    /// 召回通知。
    Recall,
}

impl CredentialType {
    /// snake_case 名称，与 serde 序列化结果一致。
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialType::EnterpriseLicense => "enterprise_license",
            CredentialType::ProductionLicense => "production_license",
            CredentialType::Origin => "origin",
            CredentialType::FoodSafetyInspection => "food_safety_inspection",
            CredentialType::QualityInspection => "quality_inspection",
            CredentialType::ColdChain => "cold_chain",
            CredentialType::Customs => "customs",
            CredentialType::Tax => "tax",
            CredentialType::Authenticity => "authenticity",
            CredentialType::Ownership => "ownership",
            CredentialType::Transport => "transport",
            CredentialType::Recall => "recall",
        }
    }
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 可验证凭证聚合根。
///
/// 字段公开：VC 本质是可序列化的数据载体（W3C VC 简化模型），
/// 构造入口 [`VerifiableCredential::new`] 保证初始不变式
/// （claims 为 object、status=Valid、hash 已计算）；反序列化同样强制校验
/// （见下方手写 `Deserialize`）。若绕过构造直接改写 claims 等字段，
/// 应同步调用 [`VerifiableCredential::compute_hash`] 刷新承诺。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiableCredential {
    /// 凭证标识符。
    pub id: CredentialId,
    /// 签发方 DID（唯一有权变更状态的主体）。
    pub issuer: Did,
    /// 凭证主体 DID（企业/批次/单品等）。
    pub subject: Did,
    /// 凭证类型。
    pub ctype: CredentialType,
    /// 主体声明集合；约定为 JSON object。
    pub claims: serde_json::Value,
    /// 签发时刻。
    pub issued_at: DateTime<Utc>,
    /// 过期时刻；`None` 表示长期有效。
    pub expires_at: Option<DateTime<Utc>>,
    /// 当前生命周期状态。
    pub status: CredStatus,
    /// 内容哈希承诺：keccak256(规范化 JSON)，不含 status 与本字段。
    pub credential_hash: Hash32,
}

impl VerifiableCredential {
    /// 构造新凭证（签发）。
    ///
    /// 约束：
    /// - `claims` 必须是 JSON object，否则返回 [`DomainError::InvalidInput`]；
    /// - 初始状态固定为 [`CredStatus::Valid`]；
    /// - [`credential_hash`](VerifiableCredential::credential_hash) 自动按
    ///   规范化 JSON 计算并写入。
    #[allow(clippy::too_many_arguments)] // VC 字段即签发入参，聚合成结构体会掩盖缺省语义
    pub fn new(
        id: CredentialId,
        issuer: Did,
        subject: Did,
        ctype: CredentialType,
        claims: serde_json::Value,
        issued_at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Self, DomainError> {
        if !claims.is_object() {
            return Err(DomainError::InvalidInput(
                "claims 必须是 JSON 对象（object）".into(),
            ));
        }
        let mut vc = Self {
            id,
            issuer,
            subject,
            ctype,
            claims,
            issued_at,
            expires_at,
            status: CredStatus::Valid,
            credential_hash: Hash32::ZERO,
        };
        vc.credential_hash = vc.compute_hash();
        Ok(vc)
    }

    /// 计算**规范化 JSON** 的 keccak256 摘要（不含 status 与 credential_hash）。
    ///
    /// 规范化策略（两种候选中的选择说明）：构造一个**不含 hash/status 的规范视图**
    /// （envelope），随后将**包括外层 envelope 在内的整棵 JSON 树**交给
    /// [`canonicalize`] 做递归键排序：
    /// 1. 排除自身派生字段，避免"哈希依赖自身"的循环定义，也让状态迁移无需重算；
    /// 2. 排序必须覆盖全部层级与外层 envelope——serde_json 默认 Map=BTreeMap
    ///    （字典序），但一旦工作区内任意 crate 启用 `preserve_order`，
    ///    Map 变为 IndexMap（插入序），未规范化的层会随 feature 开关漂移出
    ///    不同哈希；全量规范化保证同一逻辑内容在任何 serde_json feature
    ///    组合下字节串唯一；
    /// 3. 数组保序（有序列表语义不应被破坏）。
    ///
    /// 契约由 golden vector 测试固化（`hash_golden_vector_locks_canonical_format`）。
    /// 由此保证：同字段、不同插入顺序的 claims 必然产出相同哈希。
    pub fn compute_hash(&self) -> Hash32 {
        let view = serde_json::json!({
            "id": self.id,
            "issuer": self.issuer,
            "subject": self.subject,
            "ctype": self.ctype,
            "claims": self.claims,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        });
        // 整棵树（含外层 envelope 键序）递归规范化，杜绝 preserve_order 漂移
        let canonical = canonicalize(&view);
        Hash32::keccak(canonical.to_string().as_bytes())
    }

    /// 状态迁移（仅签发方可执行）。
    ///
    /// 合法迁移表：
    /// - `Valid -> Suspended` / `Valid -> Revoked`
    /// - `Suspended -> Valid` / `Suspended -> Revoked`
    ///
    /// `Revoked` / `Expired` 为终态，不可迁出。`Valid -> Expired` 不允许直接迁移：
    /// "过期"由 [`VerifiableCredential::is_effective`] 按 `expires_at` 实时判定，
    /// 持久层的 Expired 落库由外部批量任务批量处理，而非签发方手动触发。
    ///
    /// # 参数说明
    /// - `actor`：操作方 DID，必须等于签发方，否则 [`DomainError::Unauthorized`]；
    /// - `now`：调用时刻。当前状态机规则不依赖时刻，作为语义参数保留，
    ///   供上层审计日志/领域事件时间戳使用。
    ///
    /// 其余组合返回 [`DomainError::InvalidTransition`]，消息含 from/to 中文名。
    pub fn transition(
        &mut self,
        to: CredStatus,
        actor: &Did,
        now: DateTime<Utc>,
    ) -> Result<(), DomainError> {
        // 权限：仅签发方可变更凭证状态。
        if actor != &self.issuer {
            return Err(DomainError::Unauthorized(format!(
                "仅签发方 {} 可变更凭证状态，实际操作方 {}",
                self.issuer, actor
            )));
        }
        // 合法迁移表（其余组合一律拒绝，错误信息携带 from/to 中文名）。
        let allowed = matches!(
            (self.status, to),
            (CredStatus::Valid, CredStatus::Suspended)
                | (CredStatus::Valid, CredStatus::Revoked)
                | (CredStatus::Suspended, CredStatus::Valid)
                | (CredStatus::Suspended, CredStatus::Revoked)
        );
        if !allowed {
            return Err(DomainError::InvalidTransition {
                from: format!("{}({})", self.status.zh_name(), self.status),
                to: format!("{}({})", to.zh_name(), to),
            });
        }
        // `now` 当前不参与状态机规则，作为调用时刻语义参数保留，
        // 供上层审计日志/领域事件时间戳使用。
        let _ = now;
        self.status = to;
        Ok(())
    }

    /// 凭证在 `now` 时刻是否生效：状态为 [`CredStatus::Valid`] 且未过期
    /// （`now < expires_at` 或无过期时间）。过期边界即时失效。
    pub fn is_effective(&self, now: DateTime<Utc>) -> bool {
        if self.status != CredStatus::Valid {
            return false;
        }
        match self.expires_at {
            Some(expires_at) => now < expires_at,
            None => true,
        }
    }
}

/// 对任意 JSON 值做递归键排序，产出与插入顺序无关的规范化副本。
fn canonicalize(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            // 收集后按键字典序排序，再依序重建对象：
            // preserve_order 开启时按插入序保留（此处即排序后的序），
            // 未开启时 BTreeMap 自身有序，两者结果一致。
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let mut sorted = serde_json::Map::new();
            for (key, val) in entries {
                sorted.insert(key.clone(), canonicalize(val));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonicalize).collect())
        }
        other => other.clone(),
    }
}

/// 反序列化中间载体：先捕获原始字段，再统一走完整性校验。
#[derive(Deserialize)]
struct RawVc {
    id: CredentialId,
    issuer: Did,
    subject: Did,
    ctype: CredentialType,
    claims: serde_json::Value,
    issued_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    status: CredStatus,
    credential_hash: Hash32,
}

impl<'de> Deserialize<'de> for VerifiableCredential {
    /// 手写实现（与 [`crate::identity::capability::Capability`] 同一先例）：
    /// 反序列化不得绕过领域不变式——claims 必须为 object，且持久化内容与
    /// credential_hash 一致（防存储层篡改/截断），违规报 serde 数据错误。
    ///
    /// 完整性校验边界：`status` **不参与**哈希，故不在校验范围内——改写
    /// status 字段的载荷仍可通过反序列化。状态的真实性不由内容哈希保障，
    /// 而由链上 [`super::ports::CredentialAnchorPort::anchor_status`] 事件
    /// 与数据库写权限控制；消费方核验状态时应以链上锚定记录为准。
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawVc::deserialize(deserializer)?;
        if !raw.claims.is_object() {
            return Err(serde::de::Error::custom("claims 必须是 JSON 对象"));
        }
        let vc = Self {
            id: raw.id,
            issuer: raw.issuer,
            subject: raw.subject,
            ctype: raw.ctype,
            claims: raw.claims,
            issued_at: raw.issued_at,
            expires_at: raw.expires_at,
            status: raw.status,
            credential_hash: raw.credential_hash,
        };
        if vc.compute_hash() != vc.credential_hash {
            return Err(serde::de::Error::custom(
                "凭证哈希校验失败：内容与 credential_hash 不一致，可能被篡改",
            ));
        }
        Ok(vc)
    }
}

/// 凭证模式（模板）：声明某类凭证必须携带的 claims 键。
///
/// 由签发服务在落库前调用 [`CredentialSchema::validate_claims`]，
/// 保证同类型凭证的 claims 形状一致、消费方可按稳定键取值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSchema {
    /// 模式标识符（如 `"vg:schema:food-safety@v1"`）。
    pub id: String,
    /// 适用凭证类型。
    pub ctype: CredentialType,
    /// 必需的 claims 键集合；值可为任意 JSON（含 null）。
    pub required_claims: Vec<String>,
}

impl CredentialSchema {
    /// 校验 claims 是否包含全部必需键。
    ///
    /// 只检查键存在性（值为任意 JSON 均可通过）；非对象输入视为全部缺失。
    /// 缺失时返回 [`DomainError::InvalidInput`]，消息以中文列出缺失键名。
    pub fn validate_claims(&self, claims: &serde_json::Value) -> Result<(), DomainError> {
        let missing: Vec<&str> = self
            .required_claims
            .iter()
            .map(String::as_str)
            .filter(|key| claims.get(key).is_none())
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        Err(DomainError::InvalidInput(format!(
            "claims 缺少必需字段：{}",
            missing.join("、")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // ---- 公共夹具 ----

    fn issuer() -> Did {
        Did::parse("did:vg:user:ent-900").unwrap()
    }

    fn subject() -> Did {
        Did::parse("did:vg:batch:b-9001").unwrap()
    }

    fn other_actor() -> Did {
        Did::parse("did:vg:agent:ag-900").unwrap()
    }

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn sample_claims() -> serde_json::Value {
        serde_json::json!({
            "license_no": "LIC-2026-0001",
            "authority": "市场监督管理局",
            "scope": ["生产", "销售"]
        })
    }

    fn sample_vc() -> VerifiableCredential {
        VerifiableCredential::new(
            CredentialId::new("vc-001"),
            issuer(),
            subject(),
            CredentialType::FoodSafetyInspection,
            sample_claims(),
            fixed_time(),
            Some(fixed_time() + chrono::Duration::days(365)),
        )
        .expect("样例凭证构造应成功")
    }

    // ---- 1. new ----

    #[test]
    fn new_rejects_non_object_claims() {
        for bad in [
            serde_json::json!("文本"),
            serde_json::json!([1, 2, 3]),
            serde_json::json!(42),
            serde_json::json!(null),
            serde_json::json!(true),
        ] {
            let err = VerifiableCredential::new(
                CredentialId::new("vc-bad"),
                issuer(),
                subject(),
                CredentialType::Origin,
                bad,
                fixed_time(),
                None,
            )
            .expect_err("非 object 的 claims 必须被拒绝");
            assert!(
                matches!(err, DomainError::InvalidInput(_)),
                "实际错误：{err:?}"
            );
        }
    }

    #[test]
    fn new_initializes_valid_with_nonzero_computed_hash() {
        let vc = sample_vc();
        assert_eq!(vc.status, CredStatus::Valid, "初始状态必须为 Valid");
        assert!(!vc.credential_hash.is_zero(), "内容哈希不应为全零");
        assert_eq!(
            vc.compute_hash(),
            vc.credential_hash,
            "存储的哈希应与重算结果一致"
        );
        assert_eq!(vc.id, CredentialId::new("vc-001"));
        assert_eq!(vc.issuer, issuer());
        assert_eq!(vc.subject, subject());
        assert_eq!(vc.ctype, CredentialType::FoodSafetyInspection);
        assert_eq!(vc.claims, sample_claims());
    }

    // ---- 2. compute_hash 确定性 ----

    #[test]
    fn compute_hash_is_insertion_order_independent() {
        let claims_a = serde_json::json!({
            "b": {"y": 1, "x": {"d": 4, "c": 3}},
            "a": [3, 1, 2],
            "c": null
        });
        // 相同字段、不同插入顺序（顶层与嵌套对象均调换）
        let claims_b = serde_json::json!({
            "c": null,
            "a": [3, 1, 2],
            "b": {"x": {"c": 3, "d": 4}, "y": 1}
        });

        let vc_a = VerifiableCredential::new(
            CredentialId::new("vc-order"),
            issuer(),
            subject(),
            CredentialType::EnterpriseLicense,
            claims_a,
            fixed_time(),
            None,
        )
        .unwrap();
        let vc_b = VerifiableCredential::new(
            CredentialId::new("vc-order"),
            issuer(),
            subject(),
            CredentialType::EnterpriseLicense,
            claims_b,
            fixed_time(),
            None,
        )
        .unwrap();

        assert_eq!(
            vc_a.credential_hash, vc_b.credential_hash,
            "不同插入顺序的同内容 claims 必须产出相同哈希"
        );

        // 反向哨兵：内容确实不同时哈希应不同
        let vc_diff = VerifiableCredential::new(
            CredentialId::new("vc-order"),
            issuer(),
            subject(),
            CredentialType::EnterpriseLicense,
            serde_json::json!({"a": [3, 1, 2], "b": {"y": 1, "x": {"d": 9, "c": 3}}, "c": null}),
            fixed_time(),
            None,
        )
        .unwrap();
        assert_ne!(vc_a.credential_hash, vc_diff.credential_hash);
    }

    #[test]
    fn compute_hash_excludes_status_and_is_stable_across_transitions() {
        let mut vc = sample_vc();
        let before = vc.credential_hash;
        vc.transition(CredStatus::Suspended, &issuer(), fixed_time())
            .expect("Valid→Suspended 应成功");
        // status 不参与哈希：状态迁移后内容承诺保持不变
        assert_eq!(vc.compute_hash(), before);
    }

    /// Golden vector：固化"固定输入 → 固定规范化字节串 → 固定 hex 输出"的
    /// 哈希格式契约。改动哈希算法、字段集合或序列化格式之前必须三思——
    /// 该值一旦落库/上链即不可变，任何漂移都会导致历史凭证核验失败。
    #[test]
    fn hash_golden_vector_locks_canonical_format() {
        let vc = VerifiableCredential::new(
            CredentialId::new("vc-golden"),
            Did::parse("did:vg:user:ent-900").unwrap(),
            Did::parse("did:vg:batch:b-9001").unwrap(),
            CredentialType::FoodSafetyInspection,
            serde_json::json!({
                "license_no": "LIC-2026-0001",
                "authority": "市场监督管理局"
            }),
            fixed_time(),
            Some(fixed_time() + chrono::Duration::days(365)),
        )
        .unwrap();

        // 规范化字节串契约：外层 envelope 与 claims 全部按键字典序排列，
        // 不含 status / credential_hash；非 ASCII 字符按 UTF-8 原样输出不转义。
        const CANONICAL_JSON: &str = concat!(
            r#"{"claims":{"authority":"市场监督管理局","license_no":"LIC-2026-0001"},"#,
            r#""ctype":"food_safety_inspection","#,
            r#""expires_at":"2027-01-01T00:00:00Z","#,
            r#""id":"vc-golden","#,
            r#""issued_at":"2026-01-01T00:00:00Z","#,
            r#""issuer":"did:vg:user:ent-900","#,
            r#""subject":"did:vg:batch:b-9001"}"#
        );
        assert_eq!(
            vc.compute_hash(),
            Hash32::keccak(CANONICAL_JSON.as_bytes()),
            "哈希必须等于 keccak256(该规范化 JSON 字节串)"
        );
        // 固定 hex 输出（golden 值）
        assert_eq!(
            vc.compute_hash().as_hex(),
            "7415289dcf4f0213069125c9fc2c95b977138ed6d2623a4e6cd97d2eb2492557",
            "golden hex 漂移：哈希算法或序列化格式被改动"
        );
    }

    // ---- 3. transition 合法迁移 ----

    #[test]
    fn allowed_transitions_succeed() {
        // Valid → Suspended
        let mut vc = sample_vc();
        vc.transition(CredStatus::Suspended, &issuer(), fixed_time())
            .expect("Valid→Suspended 应成功");
        assert_eq!(vc.status, CredStatus::Suspended);

        // Suspended → Valid（恢复）
        vc.transition(CredStatus::Valid, &issuer(), fixed_time())
            .expect("Suspended→Valid 应成功");
        assert_eq!(vc.status, CredStatus::Valid);

        // Valid → Revoked
        let mut vc = sample_vc();
        vc.transition(CredStatus::Revoked, &issuer(), fixed_time())
            .expect("Valid→Revoked 应成功");
        assert_eq!(vc.status, CredStatus::Revoked);

        // Suspended → Revoked
        let mut vc = sample_vc();
        vc.transition(CredStatus::Suspended, &issuer(), fixed_time())
            .unwrap();
        vc.transition(CredStatus::Revoked, &issuer(), fixed_time())
            .expect("Suspended→Revoked 应成功");
        assert_eq!(vc.status, CredStatus::Revoked);
    }

    #[test]
    fn terminal_states_cannot_transition_out() {
        // Revoked 为终态：任何迁出都拒绝
        let mut revoked = sample_vc();
        revoked
            .transition(CredStatus::Revoked, &issuer(), fixed_time())
            .unwrap();
        for to in [
            CredStatus::Valid,
            CredStatus::Suspended,
            CredStatus::Revoked,
        ] {
            let err = revoked
                .transition(to, &issuer(), fixed_time())
                .expect_err("Revoked 为终态，不允许任何迁移");
            assert!(
                matches!(err, DomainError::InvalidTransition { .. }),
                "{err:?}"
            );
        }

        // Expired 为终态：任何迁出都拒绝。
        // Expired 无法经由 transition 到达（见下一条测试），此处模拟外部批量任务
        // 按 expires_at 落库后的持久化状态直接改写字段（pub 字段即为此预留）。
        let mut expired = sample_vc();
        expired.status = CredStatus::Expired;
        for to in [
            CredStatus::Valid,
            CredStatus::Suspended,
            CredStatus::Revoked,
        ] {
            let err = expired
                .transition(to, &issuer(), fixed_time())
                .expect_err("Expired 为终态，不允许任何迁移");
            assert!(
                matches!(err, DomainError::InvalidTransition { .. }),
                "{err:?}"
            );
        }
    }

    #[test]
    fn valid_to_expired_direct_transition_is_forbidden() {
        // 设计约定：过期不是签发方的主动动作——is_effective(now) 实时反映过期语义，
        // 持久层状态落库（Valid→Expired）由外部批量任务处理，故状态机禁止该直连。
        let mut vc = sample_vc();
        let err = vc
            .transition(CredStatus::Expired, &issuer(), fixed_time())
            .expect_err("Valid→Expired 不允许直接迁移");
        assert!(matches!(err, DomainError::InvalidTransition { .. }));

        // 其余未列入迁移表的组合同样拒绝（如自迁移、暂停→过期）
        let mut vc = sample_vc();
        let err = vc
            .transition(CredStatus::Valid, &issuer(), fixed_time())
            .expect_err("Valid→Valid 不在迁移表中");
        assert!(matches!(err, DomainError::InvalidTransition { .. }));

        let mut vc = sample_vc();
        vc.transition(CredStatus::Suspended, &issuer(), fixed_time())
            .unwrap();
        let err = vc
            .transition(CredStatus::Expired, &issuer(), fixed_time())
            .expect_err("Suspended→Expired 不在迁移表中");
        assert!(matches!(err, DomainError::InvalidTransition { .. }));
    }

    #[test]
    fn invalid_transition_message_contains_chinese_names_of_from_and_to() {
        let mut revoked = sample_vc();
        revoked
            .transition(CredStatus::Revoked, &issuer(), fixed_time())
            .unwrap();
        let err = revoked
            .transition(CredStatus::Valid, &issuer(), fixed_time())
            .expect_err("终态迁移应报错");
        let msg = err.to_string();
        assert!(msg.contains("非法状态迁移"), "实际消息：{msg}");
        assert!(msg.contains("已撤销"), "from 中文名缺失：{msg}");
        assert!(msg.contains("有效"), "to 中文名缺失：{msg}");

        let mut fresh = sample_vc();
        let err = fresh
            .transition(CredStatus::Expired, &issuer(), fixed_time())
            .expect_err("Valid→Expired 应报错");
        let msg = err.to_string();
        assert!(
            msg.contains("有效") && msg.contains("已过期"),
            "实际消息：{msg}"
        );
    }

    // ---- 4. transition 权限 ----

    #[test]
    fn transition_by_non_issuer_is_unauthorized() {
        let mut vc = sample_vc();
        for actor in [other_actor(), subject()] {
            let err = vc
                .transition(CredStatus::Suspended, &actor, fixed_time())
                .expect_err("非签发方必须被拒绝");
            assert!(matches!(err, DomainError::Unauthorized(_)), "{err:?}");
        }
        // 被拒后状态不得变化
        assert_eq!(vc.status, CredStatus::Valid);

        // 暂停状态下非签发方尝试恢复同样拒绝
        let mut vc = sample_vc();
        vc.transition(CredStatus::Suspended, &issuer(), fixed_time())
            .unwrap();
        let err = vc
            .transition(CredStatus::Valid, &other_actor(), fixed_time())
            .expect_err("非签发方恢复必须被拒绝");
        assert!(matches!(err, DomainError::Unauthorized(_)));
        assert_eq!(vc.status, CredStatus::Suspended);
    }

    // ---- 5. is_effective ----

    #[test]
    fn is_effective_respects_status_and_expiry_boundary() {
        let at = fixed_time();

        // Valid + 未来过期 → 生效
        let vc = sample_vc();
        assert!(vc.is_effective(at));
        assert!(vc.is_effective(at + chrono::Duration::days(364)));

        // 恰好等于过期时刻 → 失效（边界即时失效）
        assert!(!vc.is_effective(fixed_time() + chrono::Duration::days(365)));
        // 过期之后 → 失效
        assert!(!vc.is_effective(at + chrono::Duration::days(366)));

        // Revoked（未过期）→ 失效
        let mut revoked = sample_vc();
        revoked
            .transition(CredStatus::Revoked, &issuer(), at)
            .unwrap();
        assert!(!revoked.is_effective(at));

        // Suspended → 失效
        let mut suspended = sample_vc();
        suspended
            .transition(CredStatus::Suspended, &issuer(), at)
            .unwrap();
        assert!(!suspended.is_effective(at));

        // 无过期时间且 Valid → 长期生效
        let eternal = VerifiableCredential::new(
            CredentialId::new("vc-eternal"),
            issuer(),
            subject(),
            CredentialType::Ownership,
            serde_json::json!({"asset": "a-1"}),
            at,
            None,
        )
        .unwrap();
        assert!(eternal.is_effective(at));
        assert!(eternal.is_effective(at + chrono::Duration::days(3650)));
    }

    // ---- 6. validate_claims ----

    #[test]
    fn schema_validate_claims_passes_when_all_required_keys_present() {
        let schema = CredentialSchema {
            id: "vg:schema:food-safety@v1".into(),
            ctype: CredentialType::FoodSafetyInspection,
            required_claims: vec!["license_no".into(), "authority".into()],
        };
        // 值可为任意 JSON（含 null / 数组 / 嵌套对象）
        let claims = serde_json::json!({
            "license_no": "LIC-1",
            "authority": null,
            "extra": ["不受限", {"nested": true}]
        });
        schema
            .validate_claims(&claims)
            .expect("全部必需键存在应通过");
        // 空需求列表恒通过
        let empty = CredentialSchema {
            id: "vg:schema:any@v1".into(),
            ctype: CredentialType::Tax,
            required_claims: vec![],
        };
        empty
            .validate_claims(&serde_json::json!({}))
            .expect("无必需键时应通过");
    }

    #[test]
    fn schema_validate_claims_reports_missing_keys_in_chinese_message() {
        let schema = CredentialSchema {
            id: "vg:schema:origin@v1".into(),
            ctype: CredentialType::Origin,
            required_claims: vec![
                "origin_place".into(),
                "cert_code".into(),
                "inspector".into(),
            ],
        };
        let claims = serde_json::json!({"inspector": "张三"});
        let err = schema.validate_claims(&claims).expect_err("缺失键必须报错");
        assert!(
            matches!(err, DomainError::InvalidInput(_)),
            "实际错误：{err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("origin_place"), "消息应含缺失键名：{msg}");
        assert!(msg.contains("cert_code"), "消息应含缺失键名：{msg}");
        assert!(!msg.contains("inspector"), "存在的键不应列为缺失：{msg}");

        // 非对象输入视为全部缺失
        let err = schema
            .validate_claims(&serde_json::json!("垃圾"))
            .expect_err("非对象 claims 必须报错");
        assert!(err.to_string().contains("origin_place"));
    }

    // ---- 7. serde ----

    #[test]
    fn credential_type_serializes_snake_case() {
        let cases = [
            (CredentialType::EnterpriseLicense, "enterprise_license"),
            (CredentialType::ProductionLicense, "production_license"),
            (CredentialType::Origin, "origin"),
            (
                CredentialType::FoodSafetyInspection,
                "food_safety_inspection",
            ),
            (CredentialType::QualityInspection, "quality_inspection"),
            (CredentialType::ColdChain, "cold_chain"),
            (CredentialType::Customs, "customs"),
            (CredentialType::Tax, "tax"),
            (CredentialType::Authenticity, "authenticity"),
            (CredentialType::Ownership, "ownership"),
            (CredentialType::Transport, "transport"),
            (CredentialType::Recall, "recall"),
        ];
        assert_eq!(cases.len(), 12, "12 类凭证类型应全量覆盖");
        for (ctype, name) in cases {
            assert_eq!(
                serde_json::to_string(&ctype).unwrap(),
                format!("\"{name}\""),
                "{ctype:?} 序列化不符"
            );
            // Display/as_str 与 serde 命名一致
            assert_eq!(ctype.as_str(), name);
            assert_eq!(ctype.to_string(), name);
            // 反序列化回环
            let back: CredentialType =
                serde_json::from_str(&format!("\"{name}\"")).expect("应可反序列化");
            assert_eq!(back, ctype);
        }
        // 未知类型字符串拒绝
        assert!(serde_json::from_str::<CredentialType>("\"golden_ticket\"").is_err());
    }

    #[test]
    fn vc_json_roundtrip_preserves_all_fields() {
        let vc = sample_vc();
        let json = serde_json::to_string(&vc).expect("序列化应成功");
        assert!(
            json.contains("\"ctype\":\"food_safety_inspection\""),
            "类型应为小写蛇形：{json}"
        );
        assert!(
            json.contains("\"status\":\"valid\""),
            "状态应为小写蛇形：{json}"
        );

        let back: VerifiableCredential = serde_json::from_str(&json).expect("反序列化应成功");
        assert_eq!(back, vc);
    }

    #[test]
    fn deserialization_rejects_tampered_or_invalid_payloads() {
        let vc = sample_vc();
        let json = serde_json::to_string(&vc).unwrap();

        // 篡改 claims 内容但不更新 hash → 哈希校验失败
        let mut tampered: serde_json::Value = serde_json::from_str(&json).unwrap();
        tampered["claims"]["authority"] = serde_json::json!("伪造机关");
        let err = serde_json::from_value::<VerifiableCredential>(tampered)
            .expect_err("篡改内容的凭证必须被拒绝");
        assert!(
            err.to_string().contains("credential_hash"),
            "错误应说明哈希不一致：{err}"
        );

        // claims 非 object → 拒绝
        let mut non_object: serde_json::Value = serde_json::from_str(&json).unwrap();
        non_object["claims"] = serde_json::json!("数组不行");
        assert!(serde_json::from_value::<VerifiableCredential>(non_object).is_err());

        // status 未知字符串 → 拒绝
        let mut bad_status: serde_json::Value = serde_json::from_str(&json).unwrap();
        bad_status["status"] = serde_json::json!("frozen");
        assert!(serde_json::from_value::<VerifiableCredential>(bad_status).is_err());
    }

    /// 固化已知边界（M-1）：status 不参与哈希，改写 status 字段的载荷
    /// 仍可通过反序列化。这是文档化契约而非缺陷——状态真实性由链上
    /// anchor_status 事件与 DB 写权限保障，内容哈希只承诺业务字段。
    #[test]
    fn deserialization_ignores_status_field_tampering_by_design() {
        let mut vc = sample_vc();
        vc.transition(CredStatus::Revoked, &issuer(), fixed_time())
            .expect("Valid→Revoked 应成功");
        let json = serde_json::to_string(&vc).unwrap();

        // 只改 status（revoked → valid），其余字段与哈希原样保留
        let mut tampered_status: serde_json::Value = serde_json::from_str(&json).unwrap();
        tampered_status["status"] = serde_json::json!("valid");
        let back: VerifiableCredential = serde_json::from_value(tampered_status)
            .expect("status 不参与完整性校验，应可通过反序列化");
        assert_eq!(back.status, CredStatus::Valid);
        assert_ne!(back.status, vc.status, "被篡改的状态不应等于原始状态");
        // 业务字段承诺不受影响：claims/哈希与原文一致
        assert_eq!(back.claims, vc.claims);
        assert_eq!(back.credential_hash, vc.credential_hash);
    }

    /// Suspended 状态的凭证 JSON 往返无损（非 Valid 状态同样可持久化回读）。
    #[test]
    fn suspended_vc_json_roundtrip() {
        let mut vc = sample_vc();
        vc.transition(CredStatus::Suspended, &issuer(), fixed_time())
            .expect("Valid→Suspended 应成功");

        let text = serde_json::to_string(&vc).expect("序列化应成功");
        assert!(
            text.contains("\"status\":\"suspended\""),
            "暂停态应为小写蛇形：{text}"
        );

        let back: VerifiableCredential = serde_json::from_str(&text).expect("roundtrip 应成功");
        assert_eq!(back, vc);
        assert_eq!(back.status, CredStatus::Suspended);
        // 暂停态不生效，但内容承诺保持不变
        assert!(!back.is_effective(fixed_time()));
        assert_eq!(back.credential_hash, vc.credential_hash);
    }
}
