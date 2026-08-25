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
        type Context;

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
