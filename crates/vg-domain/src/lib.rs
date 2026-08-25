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

pub mod identity;
pub mod shared;

// ---- 占位：以下上下文模块由后续任务添加 ----
// pub mod credential;  // 凭证：VC、状态簿
// pub mod lifecycle;   // 生命周期：批次状态机、事件
// pub mod commodity;   // 商品：Product/Batch/Asset/Lineage
// pub mod ownership;   // 所有权：状态机与转移
// pub mod policy;      // 策略：领域策略与 ABAC
// pub mod intent;      // Intent：唯一写入口径
// pub mod privacy;     // 隐私：票据、隐形地址
