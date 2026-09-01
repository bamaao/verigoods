//! 连接池构造。
//!
//! 独立成模块便于 Task 23 bootstrap 复用，并在后续任务中统一收口
//! 池参数（连接数、超时等）而不改动调用方。

/// 以默认池参数建立连接池。
///
/// 简单封装 `PgPoolOptions`；如需限流/超时调参，在本模块内扩展。
pub async fn connect(url: &str) -> Result<sqlx::PgPool, sqlx::Error> {
    sqlx::postgres::PgPoolOptions::new().connect(url).await
}
