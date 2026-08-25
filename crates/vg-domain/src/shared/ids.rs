//! 领域标识符 newtype 集合。
//!
//! 各聚合/实体使用独立 newtype 而非裸 `String`，避免不同上下文的 ID 混用；
//! ID 既可由调用方提供字符串（如链上地址、外部编号），也可由 [`uuid::Uuid::now_v7`]
//! 生成本地时间有序 ID。

use std::fmt;

use serde::{Deserialize, Serialize};

/// 定义内部为 `String` 的标识符 newtype。
///
/// 自动获得：`Debug/Clone/PartialEq/Eq/Hash`、`Display`、serde 以纯字符串
/// 序列化，以及便捷构造：
/// - `new`：由调用方提供的字符串构造；
/// - `generate`：生成 uuid v7（时间有序）新 ID。
macro_rules! string_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            /// 由调用方提供的字符串构造。
            #[allow(clippy::new_without_default)] // 标识符没有有意义的空默认值
            pub fn new(id: impl Into<String>) -> Self {
                Self(id.into())
            }

            /// 使用 uuid v7 生成时间有序的新 ID。
            pub fn generate() -> Self {
                Self(uuid::Uuid::now_v7().to_string())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

string_id!(
    /// 批次标识符。
    BatchId
);
string_id!(
    /// 单品（资产）标识符。
    AssetId
);
string_id!(
    /// 可验证凭证标识符。
    CredentialId
);
string_id!(
    /// Intent 标识符（唯一写入口径的请求 ID）。
    IntentId
);
string_id!(
    /// 证明（ZK 证明等）标识符。
    ProofId
);
string_id!(
    /// 策略标识符。
    PolicyId
);
string_id!(
    /// 商品标识符。
    ProductId
);

/// 统一指向批次或单品的引用。
///
/// 序列化格式为 `{"type":"batch","id":"..."}` / `{"type":"asset","id":"..."}`。
///
/// 说明：serde 内部标签（internally tagged）不支持包裹字符串的 newtype 变体，
/// 因此采用相邻标签实现——tag 字段名仍为 `"type"`，取值 `"batch"`/`"asset"`，
/// 线上格式与内部标签语义一致。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
pub enum SubjectRef {
    /// 指向一个批次。
    Batch(BatchId),
    /// 指向一个单品。
    Asset(AssetId),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn new_and_display_work_for_every_id_type() {
        let batch = BatchId::new("batch-001");
        assert_eq!(batch.0, "batch-001");
        assert_eq!(batch.to_string(), "batch-001");

        // From<&str> / String 均可
        assert_eq!(AssetId::new(String::from("asset-x")).0, "asset-x");
        assert_eq!(ProductId::new("p-1"), ProductId::new("p-1"));
        assert_ne!(CredentialId::new("c1"), CredentialId::new("c2"));

        let intent = IntentId::new("i-42");
        let proof = ProofId::new("pf-1");
        let policy = PolicyId::new("pol-7");
        assert_eq!(
            (intent.to_string(), proof.to_string(), policy.to_string()),
            ("i-42".to_string(), "pf-1".to_string(), "pol-7".to_string())
        );
    }

    #[test]
    fn generate_returns_distinct_uuid_v7_strings() {
        let a = BatchId::generate();
        let b = BatchId::generate();
        assert_ne!(a, b, "两次生成的 ID 不应相同");
        for id in [&a.0, &b.0] {
            let uuid = uuid::Uuid::parse_str(id).expect("generate 应产出合法 uuid 字符串");
            assert_eq!(uuid.get_version_num(), 7, "应为 uuid v7");
        }
    }

    #[test]
    fn ids_serialize_as_plain_strings() {
        assert_eq!(
            serde_json::to_string(&BatchId::new("b1")).unwrap(),
            "\"b1\""
        );
        let back: BatchId = serde_json::from_str("\"b1\"").unwrap();
        assert_eq!(back, BatchId::new("b1"));
    }

    #[test]
    fn ids_expose_as_ref_str() {
        let batch = BatchId::new("b-77");
        assert_eq!(batch.as_ref(), "b-77");
        // 生成型 ID 同样可用 AsRef<str> 透出内部字符串
        let asset = AssetId::generate();
        assert_eq!(asset.as_ref(), asset.0);
    }

    #[test]
    fn subject_ref_serializes_with_type_tag() {
        let batch = SubjectRef::Batch(BatchId::new("b1"));
        assert_eq!(
            serde_json::to_value(&batch).unwrap(),
            json!({"type": "batch", "id": "b1"})
        );

        let asset = SubjectRef::Asset(AssetId::new("a9"));
        assert_eq!(
            serde_json::to_value(&asset).unwrap(),
            json!({"type": "asset", "id": "a9"})
        );
    }

    #[test]
    fn subject_ref_roundtrip() {
        for subject in [
            SubjectRef::Batch(BatchId::new("b2")),
            SubjectRef::Asset(AssetId::new("a1")),
        ] {
            let text = serde_json::to_string(&subject).unwrap();
            let back: SubjectRef = serde_json::from_str(&text).unwrap();
            assert_eq!(back, subject);
        }
    }

    #[test]
    fn subject_ref_rejects_unknown_type() {
        let bad = r#"{"type": "nft", "id": "x"}"#;
        let err = serde_json::from_str::<SubjectRef>(bad).expect_err("未知 type 应被拒绝");
        assert!(err.is_data() || err.is_syntax());
    }
}
