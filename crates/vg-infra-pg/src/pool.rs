//! 连接池构造。
//!
//! 独立成模块便于 Task 23 bootstrap 复用，并在后续任务中统一收口
//! 池参数（连接数、超时等）而不改动调用方。

use std::time::Duration;

/// 池内最大连接数。
// TODO(Task 23)：bootstrap 落地时移入配置。
const MAX_CONNECTIONS: u32 = 10;
/// 单次取连接的超时。
const ACQUIRE_TIMEOUT_SECS: u64 = 30;

/// 建立连接池（显式池参数：上限 / 获取超时 / 归还前探活）。
///
/// `test_before_acquire(true)`：从池中取出的陈旧连接在使用前做轻量探活，
/// 避免开发库长时间空闲后被复位连接导致的首查失败。
pub async fn connect(url: &str) -> Result<sqlx::PgPool, sqlx::Error> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .acquire_timeout(Duration::from_secs(ACQUIRE_TIMEOUT_SECS))
        .test_before_acquire(true)
        .connect(url)
        .await
}
