//! Shielded 读侧服务：Note 扫描与监管解密。
//!
//! Phase1 量级假设：全表扫描（notes 无过滤列）；接收方以 view 私钥 +
//! spend 公钥对每行一次性地址做 ECDH 试算，命中即属于自己。Phase2 再
//! 引入扫描游标/标签过滤。

use k256::{PublicKey, SecretKey};
use sqlx::Row;
use vg_domain::privacy::{CompressedPoint, OneTimeAddress};
use vg_domain::shared::{DomainError, Hash32};
use vg_infra_crypto as crypto;

use crate::deps::AppDeps;
use crate::error::AppError;

/// 扫描命中的 Note（接收方视角）。
///
/// **不返回 spend 私钥本体**——`t`（派生屏蔽因子）+ 客户端自持 spend
/// 私钥即可 `unlock_spend_key`；服务端不经手完整支出凭证。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedNote {
    /// 资产引用（`batch:bt-1` / `asset:a-1` 编码）。
    pub asset_ref: String,
    /// 金额。
    pub amount: i64,
    /// 收款方一次性地址摘要（hex）。
    pub owner_ot_addr: String,
    /// Note 承诺（hex，花费证明的对象）。
    pub commitment: String,
    /// 派生屏蔽因子 t（hex，32 字节）——解锁支出私钥的原料。
    pub t: String,
}

/// view 私钥 hex → SecretKey（64 hex；非法输入 → InvalidInput）。
fn parse_secret(hex_str: &str, what: &str) -> Result<SecretKey, AppError> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| DomainError::InvalidInput(format!("{what} 非法 hex：{e}")))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        DomainError::InvalidInput(format!("{what} 必须为 32 字节 hex"))
    })?;
    SecretKey::from_slice(&arr).map_err(|e| {
        AppError::Domain(DomainError::InvalidInput(format!("{what} 非法私钥：{e}")))
    })
}

/// 遍历全部未识别 notes，返回属于该接收方（view 私钥 + spend 公钥）的
/// Notes（Phase1 全表扫描，见模块 doc 量级假设）。
pub async fn scan_notes(
    deps: &AppDeps,
    view_priv_hex: &str,
    spend_pub_hex: &str,
) -> Result<Vec<ScannedNote>, AppError> {
    let view_priv = parse_secret(view_priv_hex, "view_priv")?;
    let pub_bytes = hex::decode(spend_pub_hex.trim_start_matches("0x"))
        .map_err(|e| DomainError::InvalidInput(format!("spend_pub 非法 hex：{e}")))?;
    let spend_pub = PublicKey::from_sec1_bytes(&pub_bytes).map_err(|e| {
        AppError::Domain(DomainError::InvalidInput(format!("spend_pub 非法公钥：{e}")))
    })?;

    let rows = sqlx::query(
        "SELECT commitment, asset_ref, owner_ot_addr, amount, addr_point, ephemeral \
         FROM notes",
    )
    .fetch_all(&deps.pool)
    .await
    .map_err(|e| DomainError::Storage(format!("notes 读取失败：{e}")))?;

    let mut hits = Vec::new();
    for row in rows {
        let addr_point: Vec<u8> = row.get("addr_point");
        let ephemeral: Vec<u8> = row.get("ephemeral");
        let (addr_point, ephemeral) = match (
            <[u8; 33]>::try_from(addr_point),
            <[u8; 33]>::try_from(ephemeral),
        ) {
            (Ok(a), Ok(e)) => (a, e),
            _ => return Err(DomainError::Storage("库中 notes 扫描列长度非法".into()).into()),
        };
        let ot = OneTimeAddress {
            addr_point: CompressedPoint::new(addr_point)
                .map_err(|e| DomainError::Storage(format!("库中 notes.addr_point 非法：{e}")))?,
            ephemeral: CompressedPoint::new(ephemeral)
                .map_err(|e| DomainError::Storage(format!("库中 notes.ephemeral 非法：{e}")))?,
        };
        let Some(info) = crypto::scan_and_unlock(&view_priv, &ot, &spend_pub) else {
            continue;
        };
        let commitment: Vec<u8> = row.get("commitment");
        let owner_ot: Vec<u8> = row.get("owner_ot_addr");
        let (commitment, owner_ot) = match (
            <[u8; 32]>::try_from(commitment),
            <[u8; 32]>::try_from(owner_ot),
        ) {
            (Ok(c), Ok(o)) => (c, o),
            _ => {
                return Err(DomainError::Storage(
                    "库中 notes 扫描列（commitment/owner_ot_addr）长度非法".into(),
                )
                .into())
            }
        };
        hits.push(ScannedNote {
            asset_ref: row.get("asset_ref"),
            amount: row.get("amount"),
            owner_ot_addr: Hash32::from_bytes(owner_ot).as_hex(),
            commitment: Hash32::from_bytes(commitment).as_hex(),
            t: hex::encode(info.t),
        });
    }
    Ok(hits)
}

/// 监管解密：ExtraData 密文 + view 私钥 → {from, to, asset, ts} JSON。
///
/// 与存储/身份无关的纯函数服务（`deps` 不参与），保持与其他服务同款
/// Result 口径。
///
/// **IAM 空转声明**：本函数只做密码学解密，**不做授权判定**——授权
/// 强制点在 Task 23 API 中间层（view 私钥持有证明 + `data_access_grants`
/// 校验的双因子，见 [`crate::services::validium::grant_data_access`]）。
/// 直接调用本函数者须自证已获授权。
pub fn regulator_decrypt(
    extra: &[u8],
    view_priv_hex: &str,
) -> Result<serde_json::Value, AppError> {
    let view_priv = parse_secret(view_priv_hex, "view_priv")?;
    let plain = crypto::ecies::decrypt_with(&view_priv, extra)
        .map_err(|e| DomainError::InvalidInput(format!("ExtraData 解密失败：{e}")))?;
    serde_json::from_slice(&plain).map_err(|e| {
        AppError::Domain(DomainError::InvalidInput(format!(
            "ExtraData 明文非法 JSON：{e}"
        )))
    })
}
