//! 领域错误 → HTTP 状态码统一映射。
//!
//! 响应体统一 JSON：`{"code": "<snake 码>", "message": "<中文消息>"}`。
//! `intent_id` 字段留给 handler 层业务响应体（定案：错误体只带
//! code + message，避免从错误字符串里反解析结构信息）。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use vg_application::AppError;
use vg_domain::shared::DomainError;

/// API 层统一错误。
#[derive(Debug)]
pub enum ApiError {
    /// 领域错误（映射表见 [`ApiError::status`]）。
    Domain(DomainError),
    /// 意图未找到（404，与资源 NotFound 的 code 区分）。
    IntentNotFound(String),
}

impl ApiError {
    /// 便捷构造 400（框架层错误统一包装，如 Json 提取失败）。
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::Domain(DomainError::InvalidInput(msg.into()))
    }

    /// 便捷构造 401（鉴权中间件复用统一响应体）。
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Domain(DomainError::Unauthorized(msg.into()))
    }

    /// HTTP 状态码映射表。
    ///
    /// InvalidInput/CredentialInvalid→400；Unauthorized→401；
    /// PolicyViolated→403；AlreadyExists/InvalidTransition/
    /// ReplayDetected/QuantityMismatch→409；NotFound→404；
    /// Storage→500。
    fn status(&self) -> StatusCode {
        match self {
            Self::Domain(e) => match e {
                DomainError::InvalidInput(_) | DomainError::CredentialInvalid(_) => {
                    StatusCode::BAD_REQUEST
                }
                DomainError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
                DomainError::PolicyViolated(_) => StatusCode::FORBIDDEN,
                DomainError::AlreadyExists
                | DomainError::InvalidTransition { .. }
                | DomainError::ReplayDetected
                | DomainError::QuantityMismatch => StatusCode::CONFLICT,
                DomainError::NotFound => StatusCode::NOT_FOUND,
                DomainError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::IntentNotFound(_) => StatusCode::NOT_FOUND,
        }
    }

    /// snake 码（作为响应体 `code`，供客户端程序化分诊）。
    fn code(&self) -> &'static str {
        match self {
            Self::IntentNotFound(_) => "intent_not_found",
            Self::Domain(e) => match e {
                DomainError::InvalidTransition { .. } => "invalid_transition",
                DomainError::NotFound => "not_found",
                DomainError::AlreadyExists => "already_exists",
                DomainError::Unauthorized(_) => "unauthorized",
                DomainError::PolicyViolated(_) => "policy_violated",
                DomainError::QuantityMismatch => "quantity_mismatch",
                DomainError::CredentialInvalid(_) => "credential_invalid",
                DomainError::ReplayDetected => "replay_detected",
                DomainError::Storage(_) => "storage",
                DomainError::InvalidInput(_) => "invalid_input",
            },
        }
    }
}

impl From<DomainError> for ApiError {
    fn from(e: DomainError) -> Self {
        Self::Domain(e)
    }
}

impl From<AppError> for ApiError {
    fn from(e: AppError) -> Self {
        match e {
            AppError::Domain(d) => Self::Domain(d),
            AppError::IntentNotFound(id) => Self::IntentNotFound(id),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let message = match &self {
            Self::IntentNotFound(id) => format!("意图未找到：{id}"),
            // Storage 错误的原始消息可能携带 DSN/SQL 细节等敏感信息：
            // 响应体一律脱敏为通用文案，原始消息仅进服务端日志
            Self::Domain(DomainError::Storage(original)) => {
                tracing::error!(code = "storage", original = %original, "内部存储错误（响应体已脱敏）");
                "内部存储错误".to_owned()
            }
            Self::Domain(e) => e.to_string(),
        };
        (
            self.status(),
            Json(json!({ "code": self.code(), "message": message })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 各 DomainError 变体 → 期望 HTTP 状态码。
    #[test]
    fn domain_error_status_mapping() {
        let cases: Vec<(DomainError, StatusCode)> = vec![
            (
                DomainError::InvalidInput("x".into()),
                StatusCode::BAD_REQUEST,
            ),
            (
                DomainError::CredentialInvalid("x".into()),
                StatusCode::BAD_REQUEST,
            ),
            (DomainError::Unauthorized("x".into()), StatusCode::UNAUTHORIZED),
            (
                DomainError::PolicyViolated("x".into()),
                StatusCode::FORBIDDEN,
            ),
            (DomainError::AlreadyExists, StatusCode::CONFLICT),
            (
                DomainError::InvalidTransition {
                    from: "a".into(),
                    to: "b".into(),
                },
                StatusCode::CONFLICT,
            ),
            (DomainError::ReplayDetected, StatusCode::CONFLICT),
            (DomainError::QuantityMismatch, StatusCode::CONFLICT),
            (DomainError::NotFound, StatusCode::NOT_FOUND),
            (
                DomainError::Storage("boom".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (err, expect) in cases {
            let resp = ApiError::Domain(err).into_response();
            assert_eq!(resp.status(), expect, "变体映射状态码应为 {expect}");
        }
    }

    /// 响应体结构：{code, message}（无 intent_id 字段）。
    #[tokio::test]
    async fn body_is_code_and_message() {
        let resp = ApiError::Domain(DomainError::NotFound).into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], "not_found");
        assert_eq!(v["message"], "目标资源不存在");
        assert!(v.get("intent_id").is_none());
    }

    /// AppError::IntentNotFound → 404 且 code=intent_not_found。
    #[tokio::test]
    async fn intent_not_found_maps_to_404() {
        let resp = ApiError::from(AppError::intent_not_found("it-1")).into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], "intent_not_found");
        assert_eq!(v["message"], "意图未找到：it-1");
    }

    /// Storage 变体：响应体为通用文案，不得泄露原始消息。
    #[tokio::test]
    async fn storage_error_body_is_sanitized() {
        let secret = "postgres://user:pass@db.internal:5432/x 连接失败";
        let resp = ApiError::Domain(DomainError::Storage(secret.into())).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["code"], "storage");
        assert_eq!(v["message"], "内部存储错误");
        assert!(!text.contains("db.internal"), "原始消息子串不得出现在响应体");
        assert!(!text.contains("连接失败"), "原始消息子串不得出现在响应体");
    }

    /// 普通领域错误经 AppError 透传保持原状态码。
    #[test]
    fn app_error_domain_passthrough() {
        let resp = ApiError::from(AppError::Domain(DomainError::AlreadyExists)).into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
}
