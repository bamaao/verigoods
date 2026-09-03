//! 统一 JSON 请求体提取器。
//!
//! Task 24 起新增 handler **一律使用 [`AppJson`] 而非裸 [`axum::Json`]**
//! 作为请求体提取器：裸 Json 提取失败时 axum 默认返回纯文本 4xx 响应，
//! 破坏 `{"code","message"}` 统一错误体契约；AppJson 将提取失败折叠为
//! `400 invalid_input`，与其他框架层错误同构。

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Json, Request};

use crate::error::ApiError;

/// JSON 请求体提取器（成功荷载透传）。
///
/// 用法：`async fn handler(AppJson(payload): AppJson<SomeDto>) -> ...`
pub struct AppJson<T>(pub T);

impl<S, T> FromRequest<S> for AppJson<T>
where
    S: Send + Sync,
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(AppJson(value)),
            Err(rejection) => {
                // 统一 JSON 错误体（400 invalid_input）；rejection 的 Display
                // 携带 axum 的具体解析原因（语法错/类型不匹配/长度超限等）
                Err(ApiError::bad_request(format!(
                    "请求体 JSON 解析失败：{rejection}"
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::Router;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    #[tokio::test]
    async fn bad_json_body_is_400_with_unified_error_body() {
        let router = Router::new().route(
            "/echo",
            post(|AppJson(v): AppJson<Value>| async move { Json(v) }),
        );
        let resp = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/echo")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from("{not json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], "invalid_input", "错误体应为统一 code：{v}");
        assert!(
            v["message"]
                .as_str()
                .unwrap()
                .contains("请求体 JSON 解析失败"),
            "message 应说明解析失败：{v}"
        );
    }

    #[tokio::test]
    async fn valid_json_body_passes_through() {
        let router = Router::new().route(
            "/echo",
            post(|AppJson(v): AppJson<Value>| async move { Json(v) }),
        );
        let resp = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/echo")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"a":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v, json!({ "a": 1 }));
    }

    /// 类型不匹配（数组送对象）同样折叠为 400 统一错误体。
    #[tokio::test]
    async fn type_mismatch_is_400_with_unified_error_body() {
        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct Dto {
            a: i64,
        }
        let router = Router::new().route("/dto", post(|AppJson(_v): AppJson<Dto>| async { "ok" }));
        let resp = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/dto")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"[1,2,3]"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["code"], "invalid_input");
    }
}
