//! 共享应用状态与内存 nonce 防重放存储。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use vg_application::IntentEngine;

/// nonce 内存存储容量上限（超限按最旧 ts 清理一条）。
pub(crate) const NONCE_CAPACITY: usize = 10_000;

/// 内存级 nonce 防重放存储。
///
/// 取舍（doc 契约）：
/// - **内存级、单实例**：重启清零、多实例部署需换共享存储（Redis 等）；
/// - 容量有限（[`NONCE_CAPACITY`]）：插入后超限即删除 ts 最小的条目
///   （近似 LRU；被清理的 nonce 理论上可重放，但已被 ts 漂移窗口
///   ≤300s 约束，可重放窗口同样受限）。
#[derive(Debug, Default)]
pub struct NonceStore {
    pub(crate) seen: Mutex<HashMap<String, i64>>,
}

impl NonceStore {
    /// 构造空存储。
    pub fn new() -> Self {
        Self::default()
    }

    /// 检查并记录 nonce：已存在返回 `false`（重放），不存在则插入并返回 `true`。
    ///
    /// 调用时机契约：**必须在签名验证通过后调用**（见 middleware/auth.rs），
    /// 避免攻击者用假签名烧毁他人 nonce 造成 DoS。
    pub fn check_and_record(&self, nonce: &str, ts: i64) -> bool {
        let mut seen = self.seen.lock().expect("nonce 存储锁中毒");
        if seen.contains_key(nonce) {
            return false;
        }
        if seen.len() >= NONCE_CAPACITY {
            // 删除 ts 最小的条目（首次命中即删，容量恒 ≤ 上限）
            if let Some(oldest) = seen.iter().min_by_key(|(_, ts)| **ts).map(|(k, _)| k.clone()) {
                seen.remove(&oldest);
            }
        }
        seen.insert(nonce.to_owned(), ts);
        true
    }
}

/// Axum 共享状态（`Arc` 包装，经 `with_state` 注入）。
pub struct AppState {
    /// 意图管道引擎（Task 24 业务路由复用）。
    pub engine: IntentEngine,
    /// 共享连接池（health 探活 / 中间件短事务）。
    pub pool: sqlx::PgPool,
    /// nonce 防重放存储。
    pub nonce_store: NonceStore,
}

/// 各 handler 使用的状态类型别名。
pub type SharedState = Arc<AppState>;
