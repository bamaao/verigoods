//! Private Validium 服务：Merkle 状态根提交与数据访问授权（IAM）。
//!
//! 悬挂锚契约：**先库后锚**——validium_batches 落库在前（库内幂等），
//! `ledger.submit_state_root` 在后（state_root 无唯一索引，每次提交各自
//! 记账、各推一次链，与 Task 18 口径一致）。

use chrono::{DateTime, Utc};
use sqlx::Row;
use vg_domain::shared::{Did, DomainError, Hash32};

use crate::deps::AppDeps;
use crate::error::AppError;

/// 批次条目哈希的 Merkle 根（keccak-256，算法写死）：
///
/// - 空 → 32 字节全零（[`Hash32::ZERO`]）；
/// - 逐层 `parent = keccak256(left ‖ right)`；
/// - 奇数个节点时**复制末节点补偶**再上行。
pub fn merkle_root(items: &[Hash32]) -> Hash32 {
    if items.is_empty() {
        return Hash32::ZERO;
    }
    let mut layer: Vec<[u8; 32]> = items.iter().map(|h| *h.as_bytes()).collect();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            layer.push(*layer.last().expect("非空层必有末节点"));
        }
        layer = layer
            .chunks_exact(2)
            .map(|pair| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                *Hash32::keccak(&buf).as_bytes()
            })
            .collect();
    }
    Hash32::from_bytes(layer[0])
}

/// 提交 Private Validium 状态根：Merkle(items) → 库（batch_ref 幂等）→
/// 账本锚定。幂等口径：同 `batch_ref` 二次提交不重复落库，返回**既有**
/// 根（不同条目集不会改写首批结果）；账本侧每次提交各记一条 state_root
/// 锚（Task 18 语义）。
///
/// `items` 为空时直接返回零根且**不锚定**——空集无信息量，锚定零根
/// 只会污染链上锚点流。
pub async fn submit_validium_root(
    deps: &AppDeps,
    batch_ref: &str,
    items: &[Hash32],
) -> Result<Hash32, AppError> {
    let root = merkle_root(items);
    if items.is_empty() {
        return Ok(root); // 零根，不落库不锚定
    }

    let mut tx = deps
        .pool
        .begin()
        .await
        .map_err(|e| DomainError::Storage(format!("事务开启失败：{e}")))?;
    let inserted = sqlx::query(
        "INSERT INTO validium_batches (root, batch_ref, submitted_at) \
         VALUES ($1, $2, $3) ON CONFLICT (batch_ref) DO NOTHING",
    )
    .bind(root.as_bytes().as_slice())
    .bind(batch_ref)
    .bind(Utc::now())
    .execute(&mut *tx)
    .await
    .map_err(|e| DomainError::Storage(format!("validium_batches 写入失败：{e}")))?;

    let effective =
        if inserted.rows_affected() == 0 {
            // 幂等分支：返回既有根（首批结果不可改写）
            let row = sqlx::query("SELECT root FROM validium_batches WHERE batch_ref = $1")
                .bind(batch_ref)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| DomainError::Storage(format!("validium_batches 读取失败：{e}")))?;
            let bytes: Vec<u8> = row.get("root");
            Hash32::from_bytes(bytes.try_into().map_err(|_| {
                DomainError::Storage("库中 validium_batches.root 长度非法".to_string())
            })?)
        } else {
            root
        };
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;

    // 先库后锚（悬挂锚契约）
    deps.ledger.submit_state_root(effective, batch_ref).await?;
    Ok(effective)
}

/// 授予监管方数据集访问权（IAM，不走 intent 管道——无对应
/// IntentAction，Phase2 扩展）。刷新语义：同 (grantee, dataset) 重复
/// 授予只**延展** `until`（`WHERE EXCLUDED.until > 既有 until`，数据库
/// 层强制不缩短，不依赖调用方自律）。
///
/// 授权消费侧（监管解密的强制校验点）在 Task 23 API 中间层：
/// view 私钥持有 + 本表校验的双因子，见
/// [`crate::services::shielded::regulator_decrypt`] 的 IAM 空转声明。
pub async fn grant_data_access(
    deps: &AppDeps,
    regulator: &Did,
    dataset: &str,
    until: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO data_access_grants (grantee, dataset, until) VALUES ($1, $2, $3) \
         ON CONFLICT (grantee, dataset) DO UPDATE SET until = EXCLUDED.until \
         WHERE EXCLUDED.until > data_access_grants.until",
    )
    .bind(regulator.as_str())
    .bind(dataset)
    .bind(until)
    .execute(&deps.pool)
    .await
    .map_err(|e| DomainError::Storage(format!("data_access_grants 写入失败：{e}")))?;
    Ok(())
}

/// 读取某授权的截止时刻（测试/诊断用；无行 → None）。
pub async fn data_access_until(
    deps: &AppDeps,
    regulator: &Did,
    dataset: &str,
) -> Result<Option<DateTime<Utc>>, AppError> {
    let row =
        sqlx::query("SELECT until FROM data_access_grants WHERE grantee = $1 AND dataset = $2")
            .bind(regulator.as_str())
            .bind(dataset)
            .fetch_optional(&deps.pool)
            .await
            .map_err(|e| DomainError::Storage(format!("data_access_grants 读取失败：{e}")))?;
    Ok(row.map(|r| r.get("until")))
}
