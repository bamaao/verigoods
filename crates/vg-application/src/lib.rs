//! # vg-application：应用层（IntentEngine 管道）。
//!
//! Intent 是全系统**唯一的写入口径**（设计文档 §4）：任何写动作先落为
//! Intent，经 [`intent_engine`] 编排的管道逐级推进（§27）：
//!
//! ```text
//! execute：事务 → Intent::new 校验 → insert（幂等/防重放）
//!   → 过期双保险 → Validated → 授权（DID/Agent/能力）
//!   → SAVEPOINT 业务段（Task 20/21/22 的 Handler）
//!        ├─ Err → 业务回滚 → Rejected（intent 留痕）→ audit(deny)
//!        ├─ AwaitingApproval（L3/L4 审批门）→ approvals 未决行 → 停在 Approved 前
//!        └─ Completed → Approved → Submitted → Confirmed → audit(allow)
//!
//! approve：审批人角色匹配 → approvals 决策（一次性）→ 业务段续跑后半程
//! ```
//!
//! 模块：
//! - [`deps`]：组合根 `AppDeps`（trait object 仓储 + 服务端口）；
//! - [`intent_engine`]：管道引擎、`IntentHandler` / `HandlerMap` 与
//!   intent→capability 动作映射；
//! - [`error`]：应用层错误（HTTP 映射属 Task 23）。

pub mod deps;
pub mod error;
pub mod handlers;
pub mod intent_engine;
pub mod services;

pub use deps::{AppDeps, PgTx};
pub use error::AppError;
pub use handlers::register_default;
pub use intent_engine::{
    required_capability, HandlerMap, HandlerOutcome, IntentEngine, IntentHandler, IntentResult,
    RawIntent,
};
pub use services::compliance::{
    check_compliance, get_required_credentials, recompute_compliance, ComplianceOutcome,
    ComplianceReport,
};
