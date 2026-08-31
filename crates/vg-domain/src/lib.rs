//! # vg-domain — VeriGoods 领域层
//!
//! 本 crate 是 VeriGoods 的**纯领域层**：只包含实体、值对象、领域规则与领域错误，
//! 不感知任何基础设施细节。
//!
//! ## 依赖约束
//! - 禁止依赖 sqlx / tokio / axum 等基础设施与运行时库；
//! - 允许依赖 serde（值对象序列化）、thiserror（错误定义）及轻量工具库；
//! - dev-dependencies 中允许引入 tokio 等用于异步测试（当前暂未需要）。
//!
//! 模块划分（后续任务逐步补充）：
//! - [`shared`]：跨限界上下文共享的值对象与领域错误；
//! - [`identity`]：身份：DID 文档、能力委托；
//! - [`credential`]：凭证：VC 聚合、状态机与上链锚定端口；
//! - [`lifecycle`]：生命周期：商品 13 态状态机（含上下架）、事件与端口；
//! - [`commodity`]：商品：商品类型/批次/单品聚合与谱系；
//! - [`ownership`]：所有权：所有权/保管分离模型、转移记录与端口；
//! - [`policy`]：策略：监管域、策略引擎与 ABAC；
//! - [`intent`]：Intent：唯一写入口径、状态机与风险分级；

pub mod commodity;
pub mod credential;
pub mod identity;
pub mod intent;
pub mod lifecycle;
pub mod ownership;
pub mod policy;
pub mod shared;

// ---- 占位：以下上下文模块由后续任务添加 ----
// pub mod privacy;     // 隐私：票据、隐形地址
