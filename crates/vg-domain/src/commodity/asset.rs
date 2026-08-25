//! 单品资产：最小可验证单元的防伪承诺载体。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::lifecycle::LifecycleState;
use crate::shared::{AssetId, Did, DomainError, Hash32, ProductId};

/// 单品（Asset）：从批次中 individuate 出的最小可验证单元。
///
/// `authenticity_commitment` 为防伪承诺（对应合约的 `bytes32 commitment`，
/// 合约侧有 "zero hash" 校验，领域层同样拒绝零哈希）；
/// `transfer_count` / `c2c_count` 分别统计普通转移次数与消费者对消费者
/// （C2C）转移次数，由所有权上下文随转移事件维护。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    /// 单品标识符。
    pub id: AssetId,
    /// 所属商品类型。
    pub product: ProductId,
    /// 制造商 DID。
    pub manufacturer: Did,
    /// 防伪承诺（不得为零哈希）。
    pub authenticity_commitment: Hash32,
    /// 创建时刻。
    pub created_at: DateTime<Utc>,
    /// 生命周期状态（与批次共用 13 态状态机）。
    pub state: LifecycleState,
    /// 普通转移次数。
    pub transfer_count: u32,
    /// C2C 转移次数。
    pub c2c_count: u32,
}

impl Asset {
    /// 创建单品资产。
    ///
    /// 规则：
    /// - `authenticity_commitment` 不得为 [`Hash32::ZERO`]
    ///   （对应合约 "zero hash" 校验，否则 [`DomainError::InvalidInput`]）；
    /// - 初始状态 [`LifecycleState::Created`]；两个计数均为 0。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: AssetId,
        product: ProductId,
        manufacturer: Did,
        authenticity_commitment: Hash32,
        created_at: DateTime<Utc>,
    ) -> Result<Self, DomainError> {
        if authenticity_commitment.is_zero() {
            return Err(DomainError::InvalidInput(
                "防伪承诺不得为零哈希（合约 zero hash 校验）".into(),
            ));
        }
        Ok(Self {
            id,
            product,
            manufacturer,
            authenticity_commitment,
            created_at,
            state: LifecycleState::Created,
            transfer_count: 0,
            c2c_count: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 0, 0, 0).unwrap()
    }

    fn maker() -> Did {
        Did::parse("did:vg:user:factory-1").unwrap()
    }

    fn commitment() -> Hash32 {
        Hash32::keccak(b"asset-commitment")
    }

    #[test]
    fn new_starts_created_with_zero_counts() {
        let a = Asset::new(
            AssetId::new("a-1"),
            ProductId::new("p-1"),
            maker(),
            commitment(),
            fixed_time(),
        )
        .expect("合法入参应构造成功");
        assert_eq!(a.id, AssetId::new("a-1"));
        assert_eq!(a.product, ProductId::new("p-1"));
        assert_eq!(a.manufacturer, maker());
        assert_eq!(a.authenticity_commitment, commitment());
        assert_eq!(a.created_at, fixed_time());
        assert_eq!(a.state, LifecycleState::Created);
        assert_eq!(a.transfer_count, 0, "初始普通转移计数应为 0");
        assert_eq!(a.c2c_count, 0, "初始 C2C 转移计数应为 0");
    }

    #[test]
    fn new_rejects_zero_commitment_like_contract_zero_hash_check() {
        let err = Asset::new(
            AssetId::new("a-2"),
            ProductId::new("p-1"),
            maker(),
            Hash32::ZERO,
            fixed_time(),
        )
        .expect_err("零哈希承诺必须被拒绝（合约 zero hash 校验）");
        assert!(
            matches!(err, DomainError::InvalidInput(ref msg) if msg.contains("零哈希")),
            "实际错误：{err:?}"
        );
    }

    #[test]
    fn serde_roundtrip_preserves_fields() {
        let a = Asset::new(
            AssetId::new("a-3"),
            ProductId::new("p-2"),
            maker(),
            commitment(),
            fixed_time(),
        )
        .expect("构造应成功");
        let text = serde_json::to_string(&a).expect("序列化应成功");
        let back: Asset = serde_json::from_str(&text).expect("反序列化应成功");
        assert_eq!(back, a);
    }
}
