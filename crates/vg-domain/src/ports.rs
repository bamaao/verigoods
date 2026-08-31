//! # 全局端口：账本（Ledger）、证明（Prover）与 Note 哈希。
//!
//! 与各上下文的仓储端口（`type Context: Send`，携带事务上下文）不同，
//! 这里的端口是**无状态服务型端口**：按 plan 约定为 `Send + Sync`、无 Context
//! 关联类型，由基础设施层各自实现（vg-infra-ledger / vg-infra-crypto）。
//! 依赖方向恒为 infra → domain。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::credential::CredStatus;
use crate::lifecycle::LifecycleState;
use crate::shared::{CredentialId, Did, DomainError, Hash32, PolicyId, SubjectRef};

/// Note 承诺哈希端口：Poseidon2 host-hash（plan 未列出，但领域只能定义端口
/// 注入——真实实现为 vg-infra-crypto 的 poseidon.rs（p3-poseidon2 KoalaBear，
/// 与电路一致，Task 10））。
///
/// 同步纯函数，无 async_trait 必要；入参即
/// [`Note::commitment_parts`](crate::privacy::Note::commitment_parts) 的
/// 规范前像词。
pub trait NoteHasher: Send + Sync {
    /// 对规范前像词序列计算 Note 承诺。
    fn note_commitment(&self, parts: &[[u8; 32]]) -> Hash32;
}

/// 域元素载体（KoalaBear 域，p3-poseidon2/Plonky3 侧使用）。
///
/// 规范为 32 字节**小端**编码；值的域合法性（是否落在素域内）由 Prover
/// 侧校验，领域层不做业务校验。newtype 与 [`Hash32`] 区分以防混用。
///
/// **32 字节 → KoalaBear 域元素的规范映射**：KoalaBear 素数约 2^64，单个
/// 32 字节值不是单域元素。Task 10（NoteHasher 实现）与 Task 11（电路）中，
/// 每个 32 字节值按确定性映射拆分为 **4 个连续小端 64-bit limb**
/// （不做归约/拒绝），即 b[0..32] → u64_le(b[0..8]) .. u64_le(b[24..32])；
/// 该拆分只存在于 hash/电路内部且两侧必须完全一致（与
/// [`Note::commitment_parts`](crate::privacy::Note::commitment_parts) 的
/// 编码规范互为配套）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldElement([u8; 32]);

impl FieldElement {
    /// 由 u64 构造（小端放入低 8 字节，高 24 字节为零）。
    pub fn from_u64(v: u64) -> Self {
        let mut inner = [0u8; 32];
        inner[..8].copy_from_slice(&v.to_le_bytes());
        Self(inner)
    }

    /// 由原始 32 字节小端编码构造（供反序列化与 infra 侧使用）。
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 原始 32 字节小端编码。
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serialize for FieldElement {
    /// 序列化为 hex 字符串（与 [`Hash32`](crate::shared::Hash32) 风格一致）。
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for FieldElement {
    /// 从 hex 字符串反序列化（恰好 64 个 hex 字符）。
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let inner: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("FieldElement 必须为 32 字节 hex"))?;
        Ok(Self(inner))
    }
}

/// 账本锚定条目：需要写到链上（Polygon CDK 合约 / Private Validium 数据可用性层）的项目。
///
/// serde 线上格式（相邻标签，tag 字段名 `"type"`，与 [`SubjectRef`](crate::shared::SubjectRef)
/// 风格协调；serde 的内部标签无法承载包裹非 map 类型的新类型变体（如
/// `Commitment(Hash32)` 序列化为字符串），故与 SubjectRef 同采用相邻标签，
/// 线上形如 `{"type":"transfer","value":{...}}`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum LedgerItem {
    /// Note 承诺（Shielded 交易的 note commitment）。
    Commitment(Hash32),
    /// 已消费 nullifier（防双花）。
    Nullifier(Hash32),
    /// 加密附加数据密文（监管可解）。
    EncryptedExtra(Vec<u8>),
    /// 明文转移记录（c2c = 跨企业主体）。
    Transfer {
        /// 转移标的。
        subject: SubjectRef,
        /// 转出方。
        from: Did,
        /// 转入方。
        to: Did,
        /// 是否跨企业（company-to-company）转移。
        c2c: bool,
    },
    /// 凭证状态锚定。
    CredentialStatus {
        /// 凭证 ID。
        id: CredentialId,
        /// 凭证内容哈希。
        hash: Hash32,
        /// 目标状态。
        status: CredStatus,
    },
    /// 生命周期状态变更锚定。
    LifecycleChange {
        /// 变更标的。
        subject: SubjectRef,
        /// 原状态。
        from: LifecycleState,
        /// 新状态。
        to: LifecycleState,
    },
    /// 策略注册（版本化内容哈希上链）。
    PolicyRegistered {
        /// 策略 ID。
        id: PolicyId,
        /// 版本号。
        version: u64,
        /// 策略内容哈希。
        hash: Hash32,
    },
}

/// 锚定回执：一次账本写入的凭证。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnchorReceipt {
    /// 账本交易引用（链上 tx hash 或 validium 批次内序号等，由实现定义）。
    pub tx_ref: String,
    /// 锚定时间。
    pub anchored_at: DateTime<Utc>,
    /// 是否为进程内（未真正上链）的回执——Private Validium 模式下大量写入
    /// 只进 validium 数据层，仅状态根最终上链。
    pub in_process: bool,
}

/// 账本端口：链上合约 / Private Validium 的统一写读抽象。
///
/// 服务型端口（plan 约定）：`Send + Sync`、无 Context——账本调用不共享
/// 调用方的事务会话，一致性由实现侧（nonce/重试/幂等）承担。
#[async_trait]
pub trait LedgerPort: Send + Sync {
    /// 锚定单个条目（承诺/nullifier/明文记录等）。
    async fn anchor(&self, item: LedgerItem) -> Result<AnchorReceipt, DomainError>;

    /// 提交 Private Validium 状态根（批量结算上链）。
    async fn submit_state_root(
        &self,
        root: Hash32,
        batch_ref: &str,
    ) -> Result<AnchorReceipt, DomainError>;

    /// nullifier 是否已被消费（双花检查）。
    async fn is_nullifier_spent(&self, n: &Hash32) -> Result<bool, DomainError>;

    /// 承诺是否已存在（链上 Note 集合成员检查）。
    async fn is_commitment_present(&self, c: &Hash32) -> Result<bool, DomainError>;
}

/// 电路规格：证明系统要执行的电路标识与公开输入。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CircuitSpec {
    /// 电路 ID（如 `note_opening`）。
    pub id: String,
    /// 电路版本（同 ID 多版本共存）。
    pub version: u64,
    /// 公开输入（域元素，规范小端编码）。
    pub public_inputs: Vec<FieldElement>,
}

/// 见证：电路的私有输入。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Witness {
    /// 秘密输入（域元素）。
    pub secrets: Vec<FieldElement>,
}

/// 证明束：一次 prove 的产物，含验证所需的公开输入回执。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProofBundle {
    /// 产出该证明的电路 ID。
    pub circuit_id: String,
    /// 电路版本。
    pub version: u64,
    /// 序列化证明本体（格式由 Prover 实现定义）。
    pub proof: Vec<u8>,
    /// 公开输入（验证侧按电路定义核对）。
    pub publics: Vec<FieldElement>,
}

/// 证明端口：ZK 证明的生成与验证（Plonky3 实电路在 vg-infra-prover）。
#[async_trait]
pub trait ProofProver: Send + Sync {
    /// 对给定电路与见证生成证明。
    async fn prove(
        &self,
        circuit: &CircuitSpec,
        witness: &Witness,
    ) -> Result<ProofBundle, DomainError>;

    /// 验证证明束（同步——纯计算，无 I/O）。
    fn verify(&self, bundle: &ProofBundle) -> Result<bool, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::{BatchId, CredentialId, Did, Hash32, PolicyId, SubjectRef};
    use serde_json::json;
    use std::future::Future;

    // ---- FieldElement ----

    #[test]
    fn field_element_from_u64_roundtrip_and_serde() {
        let f = FieldElement::from_u64(0x0102030405060708);
        // 低 8 字节小端，高位为零
        assert_eq!(&f.as_bytes()[..8], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        assert!(f.as_bytes()[8..].iter().all(|&b| b == 0));

        // serde hex 往返
        let text = serde_json::to_string(&f).unwrap();
        assert_eq!(text, format!("\"{}\"", hex::encode(f.as_bytes())));
        let back: FieldElement = serde_json::from_str(&text).unwrap();
        assert_eq!(back, f);

        // from_bytes 直通
        assert_eq!(FieldElement::from_bytes(*f.as_bytes()), f);
        // 非法 hex / 长度错误拒绝
        assert!(serde_json::from_str::<FieldElement>("\"zz\"").is_err());
        assert!(serde_json::from_str::<FieldElement>(&format!("\"{}\"", "ab".repeat(31))).is_err());
        // 0 也合法
        assert_eq!(FieldElement::from_u64(0), FieldElement::from_bytes([0u8; 32]));
    }

    // ---- LedgerItem serde ----

    fn did(s: &str) -> Did {
        Did::parse(s).unwrap()
    }

    fn sample_items() -> Vec<LedgerItem> {
        let h = Hash32::keccak(b"x");
        vec![
            LedgerItem::Commitment(h),
            LedgerItem::Nullifier(h),
            LedgerItem::EncryptedExtra(vec![1, 2, 3]),
            LedgerItem::Transfer {
                subject: SubjectRef::Batch(BatchId::new("b1")),
                from: did("did:vg:user:alice"),
                to: did("did:vg:user:bob"),
                c2c: true,
            },
            LedgerItem::CredentialStatus {
                id: CredentialId::new("c1"),
                hash: h,
                status: CredStatus::Revoked,
            },
            LedgerItem::LifecycleChange {
                subject: SubjectRef::Asset(crate::shared::AssetId::new("a1")),
                from: LifecycleState::Produced,
                to: LifecycleState::InTransit,
            },
            LedgerItem::PolicyRegistered {
                id: PolicyId::new("p1"),
                version: 3,
                hash: h,
            },
        ]
    }

    #[test]
    fn ledger_item_all_variants_roundtrip_and_tag_format() {
        for item in sample_items() {
            let text = serde_json::to_string(&item).unwrap();
            let back: LedgerItem = serde_json::from_str(&text).unwrap();
            assert_eq!(back, item);
        }

        // tag 格式断言：相邻标签 {"type": ..., "value": ...}
        let transfer = &sample_items()[3];
        let v = serde_json::to_value(transfer).unwrap();
        assert_eq!(v["type"], json!("transfer"));
        assert_eq!(v["value"]["subject"], json!({"type": "batch", "id": "b1"}));
        assert_eq!(v["value"]["from"], json!("did:vg:user:alice"));
        assert_eq!(v["value"]["c2c"], json!(true));

        let commit = &sample_items()[0];
        let v = serde_json::to_value(commit).unwrap();
        assert_eq!(v["type"], json!("commitment"));
        assert_eq!(v["value"], json!(Hash32::keccak(b"x").to_string()));

        let cred = &sample_items()[4];
        let v = serde_json::to_value(cred).unwrap();
        assert_eq!(v["type"], json!("credential_status"));
        assert_eq!(v["value"]["status"], json!("revoked"));

        let lc = &sample_items()[5];
        let v = serde_json::to_value(lc).unwrap();
        assert_eq!(v["type"], json!("lifecycle_change"));
        assert_eq!(v["value"]["from"], json!("produced"));
        assert_eq!(v["value"]["to"], json!("in_transit"));

        let pol = &sample_items()[6];
        let v = serde_json::to_value(pol).unwrap();
        assert_eq!(v["type"], json!("policy_registered"));

        // 未知 type 拒绝
        assert!(serde_json::from_str::<LedgerItem>(r#"{"type":"nonsense","value":1}"#).is_err());
    }

    // ---- AnchorReceipt / CircuitSpec / Witness / ProofBundle serde ----

    #[test]
    fn receipts_and_proof_structs_serde_roundtrip() {
        let t = Utc::now();
        let receipt = AnchorReceipt {
            tx_ref: "0xabc".into(),
            anchored_at: t,
            in_process: true,
        };
        let back: AnchorReceipt =
            serde_json::from_str(&serde_json::to_string(&receipt).unwrap()).unwrap();
        assert_eq!(back, receipt);

        let spec = CircuitSpec {
            id: "note_opening".into(),
            version: 1,
            public_inputs: vec![FieldElement::from_u64(7)],
        };
        let back: CircuitSpec =
            serde_json::from_str(&serde_json::to_string(&spec).unwrap()).unwrap();
        assert_eq!(back, spec);

        let witness = Witness {
            secrets: vec![FieldElement::from_u64(9)],
        };
        let back: Witness =
            serde_json::from_str(&serde_json::to_string(&witness).unwrap()).unwrap();
        assert_eq!(back, witness);

        let bundle = ProofBundle {
            circuit_id: "note_opening".into(),
            version: 1,
            proof: vec![0xAA, 0xBB],
            publics: vec![FieldElement::from_u64(7)],
        };
        let back: ProofBundle =
            serde_json::from_str(&serde_json::to_string(&bundle).unwrap()).unwrap();
        assert_eq!(back, bundle);
    }

    // ---- 端口形状：内存实现 + block_on 驱动 + Send/Sync 哨兵 ----

    struct MemLedger {
        commitments: Vec<Hash32>,
        nullifiers: Vec<Hash32>,
        in_process: bool,
    }

    #[async_trait]
    impl LedgerPort for MemLedger {
        async fn anchor(&self, _item: LedgerItem) -> Result<AnchorReceipt, DomainError> {
            Ok(AnchorReceipt {
                tx_ref: "mem-0".into(),
                anchored_at: Utc::now(),
                in_process: self.in_process,
            })
        }

        async fn submit_state_root(
            &self,
            _root: Hash32,
            _batch_ref: &str,
        ) -> Result<AnchorReceipt, DomainError> {
            Ok(AnchorReceipt {
                tx_ref: "mem-root".into(),
                anchored_at: Utc::now(),
                in_process: self.in_process,
            })
        }

        async fn is_nullifier_spent(&self, n: &Hash32) -> Result<bool, DomainError> {
            Ok(self.nullifiers.contains(n))
        }

        async fn is_commitment_present(&self, c: &Hash32) -> Result<bool, DomainError> {
            Ok(self.commitments.contains(c))
        }
    }

    struct MemProver;

    #[async_trait]
    impl ProofProver for MemProver {
        async fn prove(
            &self,
            circuit: &CircuitSpec,
            _witness: &Witness,
        ) -> Result<ProofBundle, DomainError> {
            Ok(ProofBundle {
                circuit_id: circuit.id.clone(),
                version: circuit.version,
                proof: vec![0x42],
                publics: circuit.public_inputs.clone(),
            })
        }

        fn verify(&self, _bundle: &ProofBundle) -> Result<bool, DomainError> {
            Ok(true)
        }
    }

    /// 极简 block_on（与 policy / intent 同款）：内存 fake 的 future 永远就绪；
    /// 领域层禁止引入 tokio 等运行时依赖。
    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        loop {
            if let std::task::Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }

    #[test]
    fn ledger_and_prover_ports_driven_by_block_on() {
        let c = Hash32::keccak(b"commit");
        let ledger = MemLedger {
            commitments: vec![c],
            nullifiers: Vec::new(),
            in_process: true,
        };
        assert!(block_on(ledger.is_commitment_present(&c)).unwrap());
        assert!(!block_on(ledger.is_nullifier_spent(&c)).unwrap());

        let receipt = block_on(ledger.anchor(LedgerItem::Commitment(c))).unwrap();
        assert!(receipt.in_process);
        let root_receipt =
            block_on(ledger.submit_state_root(Hash32::keccak(b"root"), "batch-1")).unwrap();
        assert_eq!(root_receipt.tx_ref, "mem-root");

        let prover = MemProver;
        let spec = CircuitSpec {
            id: "note_opening".into(),
            version: 1,
            public_inputs: vec![FieldElement::from_u64(5)],
        };
        let bundle = block_on(prover.prove(&spec, &Witness { secrets: Vec::new() })).unwrap();
        assert_eq!(bundle.circuit_id, "note_opening");
        assert!(prover.verify(&bundle).unwrap());
    }

    /// 编译期哨兵：端口本身必须 Send + Sync（服务型端口约定）。
    fn requires_send_sync<T: Send + Sync>(_: &T) {}

    #[test]
    fn ports_are_send_sync() {
        struct StubHasher;
        impl NoteHasher for StubHasher {
            fn note_commitment(&self, parts: &[[u8; 32]]) -> Hash32 {
                Hash32::keccak(&parts.concat())
            }
        }
        requires_send_sync::<MemLedger>(&MemLedger {
            commitments: Vec::new(),
            nullifiers: Vec::new(),
            in_process: false,
        });
        requires_send_sync::<MemProver>(&MemProver);
        requires_send_sync::<StubHasher>(&StubHasher);
    }
}
