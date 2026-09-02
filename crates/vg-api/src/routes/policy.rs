//! 监管策略：查询与注册。
//!
//! - `GET /api/v1/policies?jurisdiction=&product_type=`：`policies_for`
//!   候选全集（含未生效/已过期，生效窗口过滤属调用方语义）；
//! - `POST /api/v1/policies`：body = Policy JSON。**策略注册无对应
//!   intent action，Phase1 直连仓储**（短事务 save_policy）→ 201；
//!   `ledger.anchor(PolicyRegistered{id, version, hash})` 最后
//!   （悬挂锚契约：锚定是唯一不可逆步骤，置一切可能失败步骤之后）；
//!   `hash = keccak256(canonical json of {required, transitions})`
//!   （递归键排序，见 [`canonical_json`]）；
//! - `GET /api/v1/policies/{id}/{version}`：`find_policy` → 200/404。

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;
use vg_domain::policy::ports::PolicyRepository;
use vg_domain::policy::Policy;
use vg_domain::shared::{DomainError, Hash32, PolicyId};
use vg_infra_crypto::keccak256;

use crate::error::ApiError;
use crate::middleware::auth::AuthedDid;
use crate::routes::begin_tx;
use crate::state::SharedState;

/// 策略候选查询（辖区 + 类目）。
pub async fn list(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<Policy>>, ApiError> {
    let jurisdiction = params
        .get("jurisdiction")
        .ok_or_else(|| ApiError::bad_request("缺少必填 query 参数 jurisdiction"))?;
    let product_type = params
        .get("product_type")
        .ok_or_else(|| ApiError::bad_request("缺少必填 query 参数 product_type"))?;
    let repo = vg_infra_pg::PgPolicyRepository;
    let mut tx = begin_tx(&state.pool).await?;
    let policies = repo
        .policies_for(&mut tx, jurisdiction, product_type)
        .await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    Ok(Json(policies))
}

/// 策略注册（直写 + 最后锚定）。
pub async fn create(
    State(state): State<SharedState>,
    axum::Extension(AuthedDid(_regulator)): axum::Extension<AuthedDid>,
    crate::AppJson(policy): crate::AppJson<Policy>,
) -> Result<(StatusCode, Json<Policy>), ApiError> {
    // 先库后锚（悬挂锚契约）
    let repo = vg_infra_pg::PgPolicyRepository;
    let mut tx = begin_tx(&state.pool).await?;
    repo.save_policy(&mut tx, &policy).await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;

    // 内容哈希：keccak256(canonical json of {required, transitions})
    let canonical = canonical_json(&json!({
        "required": policy.required_credentials,
        "transitions": policy.transitions,
    }));
    let hash = Hash32::from_bytes(keccak256(canonical.as_bytes()));
    state
        .engine
        .deps()
        .ledger
        .anchor(vg_domain::ports::LedgerItem::PolicyRegistered {
            id: policy.policy_id.clone(),
            version: policy.version,
            hash,
        })
        .await?;
    Ok((StatusCode::CREATED, Json(policy)))
}

/// 按 (id, version) 精确查询。
pub async fn get(
    State(state): State<SharedState>,
    Path((id, version)): Path<(String, String)>,
) -> Result<Json<Policy>, ApiError> {
    let version: u64 = version
        .parse()
        .map_err(|_| ApiError::bad_request("version 路径参数必须为非负整数"))?;
    let repo = vg_infra_pg::PgPolicyRepository;
    let mut tx = begin_tx(&state.pool).await?;
    let policy = repo
        .find_policy(&mut tx, &PolicyId::new(id), version)
        .await?;
    tx.commit()
        .await
        .map_err(|e| DomainError::Storage(format!("事务提交失败：{e}")))?;
    policy.map(Json).ok_or(ApiError::from(DomainError::NotFound))
}

/// 递归键排序的规范化 JSON 序列化（与 VC credential_hash 的规范化口径
/// 同源：任意等价 JSON 树序列化结果字节一致）。
fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let inner: Vec<String> = sorted
                .iter()
                .map(|(k, val)| {
                    let key = serde_json::to_string(*k).expect("字符串键序列化不可失败");
                    format!("{key}:{}", canonical_json(val))
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(items) => {
            let inner: Vec<String> =
                items.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        // 其余标量：serde_json 紧凑序列化（字符串带引号、数字原样）
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// canonical_json：对象键排序、嵌套递归、数组保序。
    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let a = json!({"b": 1, "a": {"y": [1, 2], "x": "s"}});
        let b = json!({"a": {"x": "s", "y": [1, 2]}, "b": 1});
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(
            canonical_json(&json!({"b":1,"a":2})),
            r#"{"a":2,"b":1}"#
        );
    }
}
