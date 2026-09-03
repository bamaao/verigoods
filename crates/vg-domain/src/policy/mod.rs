//! policy 上下文：监管域、辖区策略与 ABAC 访问控制。
//!
//! - [`domain`]：监管域（监管机构的管辖范围声明，纯数据结构）；
//! - [`policy`]：策略聚合（凭证/证明约束 + 生效窗口）与策略引擎迁移裁决；
//! - [`abac`]：基于属性（角色 × 辖区 × 数据类别）的访问裁决；
//! - [`ports`]：策略与监管域持久化端口（由基础设施层实现）。

pub mod abac;
pub mod domain;
// plan 指定文件名 policy.rs，与目录同名触发 module_inception，按需豁免。
#[allow(clippy::module_inception)]
pub mod policy;

pub use abac::{AbacRequest, DataType, Role};
pub use domain::RegulatoryDomain;
pub use policy::{
    Policy, PolicyDecision, PolicyEngine, PolicyVersion, ProofKind, VerifiedProofRef,
};

/// policy 上下文的端口集合。
pub mod ports {
    use async_trait::async_trait;

    use crate::shared::{DomainError, PolicyId};

    use super::{Policy, RegulatoryDomain};

    /// 策略与监管域的持久化端口（Task 17 由 PostgreSQL 实现；领域层与测试用内存实现）。
    #[async_trait]
    pub trait PolicyRepository {
        /// 事务/会话上下文类型，由实现方定义。
        ///
        /// 必须为 `Send`：axum handler 要求 future 为 `Send`，
        /// 跨 `.await` 持有 ctx 时该关联类型约束是前提（与 identity 等同一约定）。
        type Context: Send;

        /// 保存监管域（按 `domain_id` 幂等）。
        async fn save_domain(
            &self,
            ctx: &mut Self::Context,
            domain: &RegulatoryDomain,
        ) -> Result<(), DomainError>;

        /// 按域 ID 查找监管域；不存在时返回 `Ok(None)`。
        async fn find_domain(
            &self,
            ctx: &mut Self::Context,
            domain_id: &str,
        ) -> Result<Option<RegulatoryDomain>, DomainError>;

        /// 保存策略（按 `(policy_id, version)` 幂等 upsert）。
        async fn save_policy(
            &self,
            ctx: &mut Self::Context,
            policy: &Policy,
        ) -> Result<(), DomainError>;

        /// 按 `(policy_id, version)` 精确查找；不存在时返回 `Ok(None)`。
        async fn find_policy(
            &self,
            ctx: &mut Self::Context,
            id: &PolicyId,
            version: u64,
        ) -> Result<Option<Policy>, DomainError>;

        /// 按辖区 + 商品类型取候选策略（含未生效/已过期，`is_active(now)`
        /// 过滤留给调用方——引擎按业务时刻判定，仓储不做时间假设）。
        async fn policies_for(
            &self,
            ctx: &mut Self::Context,
            jurisdiction: &str,
            product_type: &str,
        ) -> Result<Vec<Policy>, DomainError>;
    }
}

#[cfg(test)]
mod tests {
    use super::ports::PolicyRepository;
    use super::*;
    use crate::credential::CredentialType;
    use crate::lifecycle::LifecycleState;
    use crate::shared::{Did, DomainError, PolicyId};
    use async_trait::async_trait;
    use chrono::TimeZone;
    use std::collections::HashMap;
    use std::future::Future;

    // ---- 内存仓储：锁定端口形状，并作为存储适配器的参考实现 ----

    #[derive(Default)]
    struct MemStore {
        domains: HashMap<String, RegulatoryDomain>,
        policies: HashMap<(String, u64), Policy>,
    }

    struct MemRepo;

    #[async_trait]
    impl PolicyRepository for MemRepo {
        type Context = MemStore;

        async fn save_domain(
            &self,
            ctx: &mut Self::Context,
            domain: &RegulatoryDomain,
        ) -> Result<(), DomainError> {
            ctx.domains.insert(domain.domain_id.clone(), domain.clone());
            Ok(())
        }

        async fn find_domain(
            &self,
            ctx: &mut Self::Context,
            domain_id: &str,
        ) -> Result<Option<RegulatoryDomain>, DomainError> {
            Ok(ctx.domains.get(domain_id).cloned())
        }

        async fn save_policy(
            &self,
            ctx: &mut Self::Context,
            policy: &Policy,
        ) -> Result<(), DomainError> {
            let key = (policy.policy_id.to_string(), policy.version);
            ctx.policies.insert(key, policy.clone());
            Ok(())
        }

        async fn find_policy(
            &self,
            ctx: &mut Self::Context,
            id: &PolicyId,
            version: u64,
        ) -> Result<Option<Policy>, DomainError> {
            Ok(ctx.policies.get(&(id.to_string(), version)).cloned())
        }

        async fn policies_for(
            &self,
            ctx: &mut Self::Context,
            jurisdiction: &str,
            product_type: &str,
        ) -> Result<Vec<Policy>, DomainError> {
            Ok(ctx
                .policies
                .values()
                .filter(|p| p.jurisdiction == jurisdiction && p.product_type == product_type)
                .cloned()
                .collect())
        }
    }

    /// 极简 block_on（与 identity / credential 同款）：内存 fake 的 future
    /// 永远就绪，noop waker 即足够；领域层禁止引入 tokio 等运行时依赖。
    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        loop {
            if let std::task::Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
            // 内存实现不会真正 Pending；若意外 Pending 则自旋重试。
        }
    }

    fn t() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn sample_policy(id: &str, version: u64, jurisdiction: &str, product_type: &str) -> Policy {
        Policy {
            policy_id: PolicyId::new(id),
            version,
            authority: Did::parse("did:vg:user:reg-001").unwrap(),
            jurisdiction: jurisdiction.into(),
            product_type: product_type.into(),
            required_credentials: vec![CredentialType::Customs],
            required_proofs: vec![ProofKind::Ownership],
            transitions: vec![(LifecycleState::InWarehouse, LifecycleState::InTransit)],
            effective_at: t(),
            expires_at: None,
            active: true,
        }
    }

    fn sample_domain(id: &str) -> RegulatoryDomain {
        RegulatoryDomain {
            domain_id: id.into(),
            authority: Did::parse("did:vg:user:reg-001").unwrap(),
            jurisdiction: "CN".into(),
            product_types: vec!["food".into()],
            credential_schemas: vec![],
            effective_from: t(),
        }
    }

    #[test]
    fn policy_repository_port_roundtrips_domains_and_policies() {
        let repo = MemRepo;
        let mut ctx = MemStore::default();

        // 监管域：save → find；未保存返回 None
        let domain = sample_domain("dom-cn-food");
        block_on(repo.save_domain(&mut ctx, &domain)).expect("保存应成功");
        let found = block_on(repo.find_domain(&mut ctx, "dom-cn-food"))
            .expect("查询不应报错")
            .expect("刚保存的域应能查到");
        assert_eq!(found, domain);
        assert!(block_on(repo.find_domain(&mut ctx, "nope"))
            .expect("查询不应报错")
            .is_none());

        // 策略：同 id 不同版本共存；(id,version) 幂等 upsert
        let v1 = sample_policy("pol-x", 1, "CN", "food");
        let v2 = sample_policy("pol-x", 2, "CN", "food");
        let other = sample_policy("pol-y", 1, "EU", "food");
        let wrong_type = sample_policy("pol-z", 1, "CN", "electronics");
        for p in [&v1, &v2, &other, &wrong_type] {
            block_on(repo.save_policy(&mut ctx, p)).expect("保存应成功");
        }
        // v1 保存后，重存 v2 不影响 v1（版本键独立）
        assert_eq!(
            block_on(repo.find_policy(&mut ctx, &PolicyId::new("pol-x"), 1))
                .expect("查询不应报错")
                .expect("v1 应存在"),
            v1
        );
        assert_eq!(
            block_on(repo.find_policy(&mut ctx, &PolicyId::new("pol-x"), 2))
                .expect("查询不应报错")
                .expect("v2 应存在"),
            v2
        );
        assert!(
            block_on(repo.find_policy(&mut ctx, &PolicyId::new("pol-x"), 3))
                .expect("查询不应报错")
                .is_none()
        );

        // upsert：同 (id,version) 重存覆盖
        let mut v2b = v2.clone();
        v2b.active = false;
        block_on(repo.save_policy(&mut ctx, &v2b)).expect("重存应成功");
        assert!(
            !block_on(repo.find_policy(&mut ctx, &PolicyId::new("pol-x"), 2))
                .expect("查询不应报错")
                .expect("v2 应存在")
                .active
        );

        // policies_for：按辖区 + 商品类型过滤（含 inactive，时间过滤留给调用方）
        let candidates = block_on(repo.policies_for(&mut ctx, "CN", "food")).expect("查询不应报错");
        assert_eq!(candidates.len(), 2); // pol-x v1 / v2（pol-y=EU、pol-z=electronics 被排除）
        assert!(candidates
            .iter()
            .all(|p| p.jurisdiction == "CN" && p.product_type == "food"));
    }

    /// 编译期哨兵（与 identity / credential 同款）：`R::Context: Send`
    /// 必须由端口声明本身提供。
    fn requires_context_send<R: PolicyRepository>(ctx: R::Context) {
        fn needs_send<T: Send>(_: T) {}
        needs_send(ctx);
    }

    #[test]
    fn port_context_must_be_send() {
        requires_context_send::<MemRepo>(MemStore::default());
    }
}
