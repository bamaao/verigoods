//! 商品类型聚合：类目与元数据哈希承诺。

use serde::{Deserialize, Serialize};

use crate::shared::{DomainError, Hash32, ProductId};

/// 商品类型（Product Type）：同一类目下共享元数据结构的商品档案。
///
/// `metadata_hash` 是商品元数据的 Keccak-256 承诺，上链锚定后用于核验
/// 链下元数据未被篡改；`active` 为档案的软删除开关（不物理删除）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductType {
    /// 商品标识符。
    pub id: ProductId,
    /// 类目（如 `"milk"`、`"luxury_bag"`），非空。
    pub category: String,
    /// 元数据哈希承诺（对应合约 `bytes32`）。
    pub metadata_hash: Hash32,
    /// 档案是否有效（软删除标记）。
    pub active: bool,
}

impl ProductType {
    /// 创建商品类型档案。
    ///
    /// 规则：`category` 不得为空；`active` 初始为 `true`。
    pub fn new(
        id: ProductId,
        category: impl Into<String>,
        metadata_hash: Hash32,
    ) -> Result<Self, DomainError> {
        let category = category.into();
        if category.is_empty() {
            return Err(DomainError::InvalidInput("商品类目不能为空".into()));
        }
        Ok(Self {
            id,
            category,
            metadata_hash,
            active: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment() -> Hash32 {
        Hash32::keccak(b"product-metadata")
    }

    #[test]
    fn new_creates_active_product_with_fields() {
        let p = ProductType::new(ProductId::new("p-1"), "milk", commitment())
            .expect("合法入参应构造成功");
        assert_eq!(p.id, ProductId::new("p-1"));
        assert_eq!(p.category, "milk");
        assert_eq!(p.metadata_hash, commitment());
        assert!(p.active, "新建档案应初始有效");
    }

    #[test]
    fn new_rejects_empty_category() {
        let err = ProductType::new(ProductId::new("p-2"), "", commitment())
            .expect_err("空类目必须被拒绝");
        assert!(
            matches!(err, DomainError::InvalidInput(_)),
            "实际错误：{err:?}"
        );
        // String 入参同样走同一校验路径
        let err = ProductType::new(ProductId::new("p-3"), String::new(), commitment())
            .expect_err("空类目（String）必须被拒绝");
        assert!(matches!(err, DomainError::InvalidInput(_)));
    }

    #[test]
    fn serde_roundtrip_preserves_fields() {
        let p = ProductType::new(ProductId::new("p-9"), "cold_chain", commitment())
            .expect("构造应成功");
        let text = serde_json::to_string(&p).expect("序列化应成功");
        let back: ProductType = serde_json::from_str(&text).expect("反序列化应成功");
        assert_eq!(back, p);
    }
}
