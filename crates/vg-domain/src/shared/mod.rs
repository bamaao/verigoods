//! 跨限界上下文共享的基础值对象与领域错误。

pub mod did;
pub mod errors;
pub mod hash;
pub mod ids;

pub use did::Did;
pub use errors::DomainError;
pub use hash::Hash32;
pub use ids::{AssetId, BatchId, CredentialId, IntentId, PolicyId, ProductId, ProofId, SubjectRef};
