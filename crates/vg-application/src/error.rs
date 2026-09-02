//! 应用层错误：领域错误的薄包装（HTTP 映射属 Task 23 的 vg-api 职责）。

use vg_domain::shared::DomainError;

/// 应用层统一错误。
///
/// 最小集合：领域错误透传 + 意图未找到（`approve` 路径对不存在意图的
/// 专属语义；不落在 [`DomainError::NotFound`] 是为保留扩展位——HTTP
/// 映射层可能需要区分 404 与 409/422）。
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// 领域错误透传。
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// 意图未找到：`{0}`。
    #[error("意图未找到：{0}")]
    IntentNotFound(String),
}

impl AppError {
    /// 便捷构造：意图未找到。
    pub fn intent_not_found(id: impl Into<String>) -> Self {
        Self::IntentNotFound(id.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_stable() {
        let e = AppError::intent_not_found("it-1");
        assert_eq!(e.to_string(), "意图未找到：it-1");
        let d = AppError::Domain(DomainError::ReplayDetected);
        assert_eq!(d.to_string(), "检测到重放");
        // From 转换可用
        let d2: AppError = DomainError::NotFound.into();
        assert!(matches!(d2, AppError::Domain(_)));
    }
}
