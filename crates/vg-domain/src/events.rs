//! 领域事件：跨上下文的最终事实，outbox 模式落库并投递。
//!
//! serde 采用**内部标签** `{"event_type": "<snake_case>", ...}`——产品文档 §53
//! 不可得，此为本仓锁定的规范形（注释定死，上层 outbox/MCP 均以此为准）。
//! 所有变体均为结构体变体，内部标签可安全承载。
//! 不含时间戳字段：outbox 表已有 `created_at`，事件体不重复。

use serde::{Deserialize, Serialize};

use crate::ownership::CustodyReason;
use crate::shared::{AssetId, BatchId, CredentialId, Did, Hash32, ProductId, ProofId, SubjectRef};

/// 领域事件全集（12 个）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum DomainEvent {
    /// 批次创建。
    BatchCreated {
        /// 批次 ID。
        batch: BatchId,
        /// 所属商品。
        product: ProductId,
        /// 数量。
        quantity: u64,
        /// 生产者。
        producer: Did,
    },
    /// 批次拆分。
    BatchSplit {
        /// 被拆分的父批次。
        parent: BatchId,
        /// 拆出的子批次。
        children: Vec<BatchId>,
    },
    /// 批次合并。
    BatchMerged {
        /// 参与合并的子批次。
        children: Vec<BatchId>,
        /// 合并生成的新批次。
        new_batch: BatchId,
    },
    /// 单品建档。
    AssetCreated {
        /// 单品 ID。
        asset: AssetId,
        /// 所属商品。
        product: ProductId,
        /// 制造商。
        manufacturer: Did,
    },
    /// 凭证签发。
    CredentialIssued {
        /// 凭证 ID。
        credential: CredentialId,
        /// 签发方。
        issuer: Did,
        /// 持有主体。
        subject: Did,
    },
    /// 凭证撤销。
    CredentialRevoked {
        /// 凭证 ID。
        credential: CredentialId,
        /// 撤销执行者。
        by: Did,
    },
    /// 保管变更（物流链路，不改变所有权）。
    CustodyChanged {
        /// 变更标的。
        subject: SubjectRef,
        /// 原保管方（首任无前序保管方）。
        from: Option<Did>,
        /// 新保管方。
        to: Did,
        /// 变更原因。
        reason: CustodyReason,
    },
    /// 所有权转移。
    OwnershipTransferred {
        /// 转移标的。
        subject: SubjectRef,
        /// 转出方。
        from: Did,
        /// 转入方。
        to: Did,
        /// 是否跨企业（company-to-company）。
        c2c: bool,
        /// 该标的的累计转移次数（审计用）。
        transfer_count: u32,
    },
    /// 合规状态变更。
    ComplianceChanged {
        /// 变更标的。
        subject: SubjectRef,
        /// 是否合规。
        compliant: bool,
    },
    /// 商品召回。
    ProductRecalled {
        /// 召回标的。
        subject: SubjectRef,
        /// 召回原因（可缺省）。
        reason: Option<String>,
    },
    /// ZK 证明落档。
    ProofRecorded {
        /// 证明 ID。
        proof: ProofId,
        /// 电路 ID。
        circuit_id: String,
        /// 是否验证通过。
        verified: bool,
    },
    /// Private Validium 状态根提交上链。
    StateRootSubmitted {
        /// 状态根。
        root: Hash32,
        /// 批次引用。
        batch_ref: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn did(s: &str) -> Did {
        Did::parse(s).unwrap()
    }

    fn sample_events() -> Vec<DomainEvent> {
        let subject = || SubjectRef::Batch(BatchId::new("b1"));
        vec![
            DomainEvent::BatchCreated {
                batch: BatchId::new("b1"),
                product: ProductId::new("p1"),
                quantity: 100,
                producer: did("did:vg:user:alice"),
            },
            DomainEvent::BatchSplit {
                parent: BatchId::new("b1"),
                children: vec![BatchId::new("b2"), BatchId::new("b3")],
            },
            DomainEvent::BatchMerged {
                children: vec![BatchId::new("b2"), BatchId::new("b3")],
                new_batch: BatchId::new("b4"),
            },
            DomainEvent::AssetCreated {
                asset: AssetId::new("a1"),
                product: ProductId::new("p1"),
                manufacturer: did("did:vg:user:carol"),
            },
            DomainEvent::CredentialIssued {
                credential: CredentialId::new("c1"),
                issuer: did("did:vg:agent:issuer"),
                subject: did("did:vg:user:dave"),
            },
            DomainEvent::CredentialRevoked {
                credential: CredentialId::new("c1"),
                by: did("did:vg:agent:issuer"),
            },
            DomainEvent::CustodyChanged {
                subject: subject(),
                from: None,
                to: did("did:vg:user:logistics"),
                reason: CustodyReason::Ship,
            },
            DomainEvent::OwnershipTransferred {
                subject: subject(),
                from: did("did:vg:user:alice"),
                to: did("did:vg:user:bob"),
                c2c: true,
                transfer_count: 3,
            },
            DomainEvent::ComplianceChanged {
                subject: subject(),
                compliant: false,
            },
            DomainEvent::ProductRecalled {
                subject: subject(),
                reason: Some("质量问题".into()),
            },
            DomainEvent::ProofRecorded {
                proof: ProofId::new("pf1"),
                circuit_id: "note_opening".into(),
                verified: true,
            },
            DomainEvent::StateRootSubmitted {
                root: Hash32::keccak(b"root"),
                batch_ref: "batch-42".into(),
            },
        ]
    }

    #[test]
    fn all_variants_roundtrip() {
        for event in sample_events() {
            let text = serde_json::to_string(&event).unwrap();
            let back: DomainEvent = serde_json::from_str(&text).unwrap();
            assert_eq!(back, event, "往返失败：{text}");
        }
    }

    #[test]
    fn event_type_tag_names_are_snake_case() {
        let tags: Vec<(&'static str, serde_json::Value)> = vec![
            ("batch_created", serde_json::to_value(&sample_events()[0]).unwrap()),
            ("batch_split", serde_json::to_value(&sample_events()[1]).unwrap()),
            ("batch_merged", serde_json::to_value(&sample_events()[2]).unwrap()),
            ("asset_created", serde_json::to_value(&sample_events()[3]).unwrap()),
            ("credential_issued", serde_json::to_value(&sample_events()[4]).unwrap()),
            ("credential_revoked", serde_json::to_value(&sample_events()[5]).unwrap()),
            ("custody_changed", serde_json::to_value(&sample_events()[6]).unwrap()),
            ("ownership_transferred", serde_json::to_value(&sample_events()[7]).unwrap()),
            ("compliance_changed", serde_json::to_value(&sample_events()[8]).unwrap()),
            ("product_recalled", serde_json::to_value(&sample_events()[9]).unwrap()),
            ("proof_recorded", serde_json::to_value(&sample_events()[10]).unwrap()),
            ("state_root_submitted", serde_json::to_value(&sample_events()[11]).unwrap()),
        ];
        for (expected, v) in tags {
            assert_eq!(v["event_type"], json!(expected), "标签名断言失败：{v}");
            // 内部标签：字段与 event_type 平铺在同一对象
            assert!(v.as_object().unwrap().len() > 1);
        }
    }

    #[test]
    fn tag_and_field_wire_format_spot_checks() {
        let v = serde_json::to_value(&sample_events()[7]).unwrap();
        assert_eq!(
            v,
            json!({
                "event_type": "ownership_transferred",
                "subject": {"type": "batch", "id": "b1"},
                "from": "did:vg:user:alice",
                "to": "did:vg:user:bob",
                "c2c": true,
                "transfer_count": 3
            })
        );

        let v = serde_json::to_value(&sample_events()[6]).unwrap();
        assert_eq!(v["from"], json!(null), "首任保管 from 为 null");
        assert_eq!(v["reason"], json!("ship"));

        let v = serde_json::to_value(&sample_events()[11]).unwrap();
        assert_eq!(v["root"], json!(Hash32::keccak(b"root").to_string()));
        assert_eq!(v["batch_ref"], json!("batch-42"));

        // 未知 event_type 拒绝
        assert!(
            serde_json::from_str::<DomainEvent>(r#"{"event_type":"nonsense"}"#).is_err()
        );
    }
}
