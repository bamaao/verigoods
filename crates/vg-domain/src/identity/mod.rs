//! 身份上下文：DID 文档、验证方法与能力委托。
//!
//! - [`document`]：`did:vg:` DID 文档结构与父子主体约束；
//! - [`capability`]：企业 → 智能体的能力委托与执行前校验；
//! - [`ports`]：仓储端口（由基础设施层实现，领域层只定义契约）。

pub mod capability;
pub mod document;

/// 身份上下文的仓储端口。
///
/// 实现方为具体存储适配器（如 PostgreSQL）；领域层与测试可用内存实现。
pub mod ports {
    use async_trait::async_trait;

    use crate::identity::capability::Capability;
    use crate::identity::document::DidDocument;
    use crate::shared::{Did, DomainError};

    /// 身份聚合的持久化端口。
    #[async_trait]
    pub trait IdentityRepository {
        /// 事务/会话上下文类型，由实现方定义。
        ///
        /// 必须为 `Send`：axum handler（Task 19）要求 future 为 `Send`，
        /// 跨 `.await` 持有 ctx 时该关联类型约束是前提，避免到处补 where。
        type Context: Send;

        /// 保存或整体替换 DID 文档（按 `doc.did` 幂等）。
        async fn save_document(
            &self,
            ctx: &mut Self::Context,
            doc: &DidDocument,
        ) -> Result<(), DomainError>;

        /// 按 DID 查找 DID 文档；不存在时返回 `Ok(None)`。
        async fn find_document(
            &self,
            ctx: &mut Self::Context,
            did: &Did,
        ) -> Result<Option<DidDocument>, DomainError>;

        /// 写入一条能力委托。
        async fn grant_capability(
            &self,
            ctx: &mut Self::Context,
            cap: &Capability,
        ) -> Result<(), DomainError>;

        /// 列出某智能体持有的全部能力委托（含已过期，由调用方过滤）。
        async fn capabilities_of(
            &self,
            ctx: &mut Self::Context,
            agent: &Did,
        ) -> Result<Vec<Capability>, DomainError>;
    }
}

pub use capability::{assert_allowed, Action, Capability};
pub use document::{DidDocument, KeyType, SubjectKind, VerificationMethod};

#[cfg(test)]
mod tests {
    use super::ports::IdentityRepository;
    use super::*;
    use crate::shared::{Did, DomainError};
    use async_trait::async_trait;
    use chrono::TimeZone;
    use std::collections::HashMap;
    use std::future::Future;

    /// 内存仓储：锁定端口形状，并作为后续存储适配器的参考实现。
    struct MemRepo;

    /// 事务/会话上下文（Send，可被 axum handler 的 Send future 跨 await 持有）。
    #[derive(Default)]
    struct MemStore {
        docs: HashMap<Did, DidDocument>,
        caps: Vec<Capability>,
    }

    #[async_trait]
    impl IdentityRepository for MemRepo {
        type Context = MemStore;

        async fn save_document(
            &self,
            ctx: &mut Self::Context,
            doc: &DidDocument,
        ) -> Result<(), DomainError> {
            ctx.docs.insert(doc.did.clone(), doc.clone());
            Ok(())
        }

        async fn find_document(
            &self,
            ctx: &mut Self::Context,
            did: &Did,
        ) -> Result<Option<DidDocument>, DomainError> {
            Ok(ctx.docs.get(did).cloned())
        }

        async fn grant_capability(
            &self,
            ctx: &mut Self::Context,
            cap: &Capability,
        ) -> Result<(), DomainError> {
            ctx.caps.push(cap.clone());
            Ok(())
        }

        async fn capabilities_of(
            &self,
            ctx: &mut Self::Context,
            agent: &Did,
        ) -> Result<Vec<Capability>, DomainError> {
            Ok(ctx
                .caps
                .iter()
                .filter(|c| c.agent() == agent)
                .cloned()
                .collect())
        }
    }

    /// 极简 `block_on`：内存 fake 的 future 永远就绪，noop waker 即足够；
    /// 领域层禁止引入 tokio 等运行时依赖，故测试自带最小驱动器。
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

    fn fixed_time() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn enterprise_doc() -> DidDocument {
        let did = Did::parse("did:vg:user:ent-100").unwrap();
        DidDocument {
            did: did.clone(),
            kind: SubjectKind::Enterprise,
            methods: vec![VerificationMethod::new(
                "k-0",
                KeyType::Secp256k1,
                crate::shared::Hash32::keccak(b"pk"),
                did.clone(),
            )],
            parent: None,
            jurisdiction: Some("CN".into()),
            created_at: fixed_time(),
        }
    }

    #[test]
    fn identity_repository_port_roundtrips_documents_and_capabilities() {
        let repo = MemRepo;
        let mut ctx = MemStore::default();

        // DID 文档：保存 → 查到 → 未保存的返回 None
        let doc = enterprise_doc();
        let ent_did = doc.did.clone();
        block_on(repo.save_document(&mut ctx, &doc)).expect("保存文档应成功");
        let found = block_on(repo.find_document(&mut ctx, &ent_did))
            .expect("查询不应报错")
            .expect("刚保存的文档应能查到");
        assert_eq!(found, doc);
        let missing =
            block_on(repo.find_document(&mut ctx, &Did::parse("did:vg:user:none").unwrap()))
                .expect("查询不应报错");
        assert!(missing.is_none());

        // 能力委托：写入 → 按 agent 过滤查回 → 其他 agent 为空
        let ag = Did::parse("did:vg:agent:ag-100").unwrap();
        let cap = Capability::new(ag.clone(), Action::CreateBatch, ent_did, None)
            .expect("企业授权应成功");
        block_on(repo.grant_capability(&mut ctx, &cap)).expect("写入能力应成功");
        let caps = block_on(repo.capabilities_of(&mut ctx, &ag)).expect("查询能力应成功");
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0], cap);
        let other =
            block_on(repo.capabilities_of(&mut ctx, &Did::parse("did:vg:agent:ag-101").unwrap()))
                .expect("查询能力应成功");
        assert!(other.is_empty());
    }

    /// 编译期哨兵：不带任何本地 where 子句，`R::Context: Send` 必须由
    /// 端口声明本身提供。axum handler（Task 19）要求 Send future，
    /// 跨 await 持有 ctx 的前提就是该关联类型约束存在。
    fn requires_context_send<R: IdentityRepository>(ctx: R::Context) {
        fn needs_send<T: Send>(_: T) {}
        needs_send(ctx);
    }

    #[test]
    fn port_context_must_be_send() {
        requires_context_send::<MemRepo>(MemStore::default());
    }
}
