//! 凭证上下文：可验证凭证（VC）聚合、状态机与端口。
//!
//! - [`status`]：凭证生命周期状态枚举；
//! - [`vc`]：VC 聚合根（内容哈希承诺 + 签发方状态机）与凭证模式；
//! - [`ports`]：持久化与上链锚定端口（由基础设施层实现，领域层只定义契约）。

pub mod status;
pub mod vc;

pub use status::CredStatus;
pub use vc::{CredentialSchema, CredentialType, VerifiableCredential};

/// 凭证上下文的端口集合。
pub mod ports {
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};

    use crate::shared::{CredentialId, Did, DomainError, Hash32};

    use super::{CredStatus, VerifiableCredential};

    /// VC 聚合的持久化端口。
    ///
    /// 实现方为具体存储适配器（如 PostgreSQL，Task 15）；领域层与测试用内存实现。
    #[async_trait]
    pub trait CredentialRepository {
        /// 事务/会话上下文类型，由实现方定义。
        ///
        /// 必须为 `Send`：axum handler 要求 future 为 `Send`，
        /// 跨 `.await` 持有 ctx 时该关联类型约束是前提（与 identity 同一约定）。
        type Context: Send;

        /// 保存或整体替换凭证（按 `vc.id` 幂等）。
        async fn save(
            &self,
            ctx: &mut Self::Context,
            vc: &VerifiableCredential,
        ) -> Result<(), DomainError>;

        /// 按凭证 ID 查找；不存在时返回 `Ok(None)`。
        async fn find(
            &self,
            ctx: &mut Self::Context,
            id: &CredentialId,
        ) -> Result<Option<VerifiableCredential>, DomainError>;

        /// 列出某主体的全部凭证（含已失效，由调用方按需过滤）。
        async fn list_by_subject(
            &self,
            ctx: &mut Self::Context,
            subject: &Did,
        ) -> Result<Vec<VerifiableCredential>, DomainError>;

        /// 乐观锁式状态更新：仅当当前状态等于 `expected` 时置为 `next`
        /// （供批量过期任务做 Valid→Expired 的并发安全落库）。
        ///
        /// - 凭证不存在 → [`DomainError::NotFound`]；
        /// - 当前状态与 `expected` 不符 → [`DomainError::InvalidTransition`]
        ///   （from=当前实际状态、to=期望的下一状态）；
        /// - `at` 为状态生效时刻，供实现方审计落库使用。
        ///
        /// 注意：状态不参与 `credential_hash`，故本方法不改动内容哈希承诺。
        async fn update_status(
            &self,
            ctx: &mut Self::Context,
            id: &CredentialId,
            expected: CredStatus,
            next: CredStatus,
            at: DateTime<Utc>,
        ) -> Result<(), DomainError>;
    }

    /// 凭证上链锚定端口（infra 实现：InProcessLedger / alloy，Task 18/26）。
    ///
    /// 将凭证签发与状态变更以事件形式写入账本，供链下/链上核验方对账。
    #[async_trait]
    pub trait CredentialAnchorPort: Send + Sync {
        /// 锚定"签发"事件：凭证 ID 与内容哈希承诺上链。
        async fn anchor_issued(&self, id: &CredentialId, hash: &Hash32) -> Result<(), DomainError>;

        /// 锚定"状态变更"事件：凭证 ID 与新状态上链。
        async fn anchor_status(
            &self,
            id: &CredentialId,
            status: CredStatus,
        ) -> Result<(), DomainError>;
    }
}

#[cfg(test)]
mod tests {
    use super::ports::{CredentialAnchorPort, CredentialRepository};
    use super::*;
    use crate::shared::{CredentialId, Did, DomainError, Hash32};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use std::collections::HashMap;
    use std::future::Future;

    // ---- 内存仓储：锁定端口形状，并作为存储适配器的参考实现 ----

    #[derive(Default)]
    struct MemStore {
        vcs: HashMap<CredentialId, VerifiableCredential>,
    }

    struct MemRepo;

    #[async_trait]
    impl CredentialRepository for MemRepo {
        type Context = MemStore;

        async fn save(
            &self,
            ctx: &mut Self::Context,
            vc: &VerifiableCredential,
        ) -> Result<(), DomainError> {
            ctx.vcs.insert(vc.id.clone(), vc.clone());
            Ok(())
        }

        async fn find(
            &self,
            ctx: &mut Self::Context,
            id: &CredentialId,
        ) -> Result<Option<VerifiableCredential>, DomainError> {
            Ok(ctx.vcs.get(id).cloned())
        }

        async fn list_by_subject(
            &self,
            ctx: &mut Self::Context,
            subject: &Did,
        ) -> Result<Vec<VerifiableCredential>, DomainError> {
            Ok(ctx
                .vcs
                .values()
                .filter(|vc| &vc.subject == subject)
                .cloned()
                .collect())
        }

        async fn update_status(
            &self,
            ctx: &mut Self::Context,
            id: &CredentialId,
            expected: CredStatus,
            next: CredStatus,
            _at: DateTime<Utc>,
        ) -> Result<(), DomainError> {
            let vc = ctx.vcs.get_mut(id).ok_or(DomainError::NotFound)?;
            if vc.status != expected {
                return Err(DomainError::InvalidTransition {
                    from: format!("{}({})", vc.status.zh_name(), vc.status),
                    to: format!("{}({})", next.zh_name(), next),
                });
            }
            vc.status = next;
            Ok(())
        }
    }

    /// 内存锚定 fake：记录调用序列供断言；字段须 Send+Sync 以满足端口约束。
    #[derive(Default)]
    struct MemAnchor {
        log: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl CredentialAnchorPort for MemAnchor {
        async fn anchor_issued(&self, id: &CredentialId, hash: &Hash32) -> Result<(), DomainError> {
            self.log.lock().unwrap().push(format!("issued:{id}:{hash}"));
            Ok(())
        }

        async fn anchor_status(
            &self,
            id: &CredentialId,
            status: CredStatus,
        ) -> Result<(), DomainError> {
            self.log
                .lock()
                .unwrap()
                .push(format!("status:{id}:{status}"));
            Ok(())
        }
    }

    /// 极简 block_on：内存 fake 的 future 永远就绪，noop waker 即足够；
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

    fn issuer() -> Did {
        Did::parse("did:vg:user:ent-700").unwrap()
    }

    fn sample_vc(id: &str) -> VerifiableCredential {
        VerifiableCredential::new(
            CredentialId::new(id),
            issuer(),
            Did::parse("did:vg:user:ent-701").unwrap(),
            CredentialType::ColdChain,
            serde_json::json!({"temp_range": "2~8℃"}),
            fixed_time(),
            None,
        )
        .expect("样例凭证应构造成功")
    }

    #[test]
    fn credential_repository_port_roundtrips_and_updates_status() {
        let repo = MemRepo;
        let mut ctx = MemStore::default();

        // save → find 回读一致；未保存的返回 None
        let vc = sample_vc("vc-700");
        let vid = vc.id.clone();
        let subject_did = vc.subject.clone();
        block_on(repo.save(&mut ctx, &vc)).expect("保存应成功");
        let found = block_on(repo.find(&mut ctx, &vid))
            .expect("查询不应报错")
            .expect("刚保存的凭证应能查到");
        assert_eq!(found, vc);
        let missing =
            block_on(repo.find(&mut ctx, &CredentialId::new("nope"))).expect("查询不应报错");
        assert!(missing.is_none());

        // list_by_subject：命中该主体的凭证，排除其他主体
        let others = sample_vc_with_subject("vc-701", "did:vg:user:ent-999");
        block_on(repo.save(&mut ctx, &others)).expect("保存应成功");
        let listed = block_on(repo.list_by_subject(&mut ctx, &subject_did)).expect("查询不应报错");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, vid);

        // update_status：expected 匹配时更新生效
        block_on(repo.update_status(
            &mut ctx,
            &vid,
            CredStatus::Valid,
            CredStatus::Expired,
            fixed_time(),
        ))
        .expect("乐观锁匹配应更新成功");
        let updated = block_on(repo.find(&mut ctx, &vid))
            .unwrap()
            .expect("应仍存在");
        assert_eq!(updated.status, CredStatus::Expired);
        // 内容哈希不受状态影响
        assert_eq!(updated.credential_hash, vc.credential_hash);

        // update_status：expected 不匹配 → InvalidTransition（from=实际状态）
        let err = block_on(repo.update_status(
            &mut ctx,
            &vid,
            CredStatus::Valid,
            CredStatus::Revoked,
            fixed_time(),
        ))
        .expect_err("expected 与实际不符必须报错");
        assert!(
            matches!(err, DomainError::InvalidTransition { .. }),
            "实际错误：{err:?}"
        );

        // update_status：ID 不存在 → NotFound
        let err = block_on(repo.update_status(
            &mut ctx,
            &CredentialId::new("nope"),
            CredStatus::Valid,
            CredStatus::Expired,
            fixed_time(),
        ))
        .expect_err("不存在的凭证必须报 NotFound");
        assert!(matches!(err, DomainError::NotFound));
    }

    fn sample_vc_with_subject(id: &str, subject: &str) -> VerifiableCredential {
        VerifiableCredential::new(
            CredentialId::new(id),
            issuer(),
            Did::parse(subject).unwrap(),
            CredentialType::Origin,
            serde_json::json!({"place": "云南"}),
            fixed_time(),
            None,
        )
        .expect("样例凭证应构造成功")
    }

    #[test]
    fn credential_anchor_port_records_events() {
        let anchor = MemAnchor::default();
        let id = CredentialId::new("vc-800");
        let hash = Hash32::keccak(b"content");

        block_on(anchor.anchor_issued(&id, &hash)).expect("锚定签发应成功");
        block_on(anchor.anchor_status(&id, CredStatus::Revoked)).expect("锚定状态应成功");

        let log = anchor.log.lock().unwrap().join("\n");
        assert!(
            log.contains(&format!("issued:{id}:{hash}")),
            "实际日志：{log}"
        );
        assert!(
            log.contains(&format!("status:{id}:revoked")),
            "状态事件应为 snake_case 文本：{log}"
        );
    }

    /// 编译期哨兵（与 identity 同款）：`R::Context: Send` 必须由端口声明本身提供。
    fn requires_context_send<R: CredentialRepository>(ctx: R::Context) {
        fn needs_send<T: Send>(_: T) {}
        needs_send(ctx);
    }

    #[test]
    fn port_context_must_be_send() {
        requires_context_send::<MemRepo>(MemStore::default());
    }
}
