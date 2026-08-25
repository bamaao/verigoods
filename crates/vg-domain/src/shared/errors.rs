//! 领域统一错误类型。
//!
//! 所有上下文的业务错误都收敛到 [`DomainError`]，便于上层（application/api）
//! 统一映射为 HTTP 状态码或 MCP 错误。

/// 领域层统一错误。
#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    /// 非法状态迁移（如生命周期状态机不允许的跳转）。
    #[error("非法状态迁移：{from} -> {to}")]
    InvalidTransition { from: String, to: String },
    /// 目标资源不存在。
    #[error("目标资源不存在")]
    NotFound,
    /// 资源已存在（幂等冲突）。
    #[error("资源已存在")]
    AlreadyExists,
    /// 未授权操作，携带原因。
    #[error("未授权操作：{0}")]
    Unauthorized(String),
    /// 违反策略约束，携带策略说明。
    #[error("违反策略约束：{0}")]
    PolicyViolated(String),
    /// 数量不一致（如批次拆分数量与凭据数量对不上）。
    #[error("数量不一致")]
    QuantityMismatch,
    /// 凭证无效，携带原因。
    #[error("凭证无效：{0}")]
    CredentialInvalid(String),
    /// 检测到重放（nonce/jti 已被使用）。
    #[error("检测到重放")]
    ReplayDetected,
    /// 存储层错误透传。
    #[error("存储层错误：{0}")]
    Storage(String),
    /// 输入不合法，携带原因。
    #[error("输入不合法：{0}")]
    InvalidInput(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;

    /// 编译期断言：DomainError 实现 std::error::Error（含 Send/Sync 语义由编译器保证）。
    #[test]
    fn domain_error_implements_std_error() {
        fn assert_std_error<T: StdError>(err: &T) {
            // Display 与 source 可用即可
            let _ = err.to_string();
            assert!(err.source().is_none());
        }
        let err = DomainError::NotFound;
        assert_std_error(&err);
    }

    #[test]
    fn display_messages_are_chinese_and_carry_context() {
        let e = DomainError::InvalidTransition {
            from: "draft".into(),
            to: "shipped".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("非法状态迁移"), "实际消息：{msg}");
        assert!(
            msg.contains("draft") && msg.contains("shipped"),
            "实际消息：{msg}"
        );

        let e = DomainError::Unauthorized("无有效凭证".into());
        assert!(e.to_string().contains("未授权操作"));
        assert!(e.to_string().contains("无有效凭证"));

        let e = DomainError::PolicyViolated("召回批次禁止转移".into());
        assert!(e.to_string().contains("违反策略约束"));

        let e = DomainError::CredentialInvalid("签名不匹配".into());
        assert!(e.to_string().contains("凭证无效"));

        let e = DomainError::Storage("连接失败".into());
        assert!(e.to_string().contains("存储层错误"));

        let e = DomainError::InvalidInput("DID 为空".into());
        assert!(e.to_string().contains("输入不合法"));

        assert_eq!(DomainError::NotFound.to_string(), "目标资源不存在");
        assert_eq!(DomainError::AlreadyExists.to_string(), "资源已存在");
        assert_eq!(DomainError::QuantityMismatch.to_string(), "数量不一致");
        assert_eq!(DomainError::ReplayDetected.to_string(), "检测到重放");
    }
}
