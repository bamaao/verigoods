//! Task 21/22 应用服务：隐私侧读/结算与合规重算/查询用例。
//!
//! - [`shielded`]：Note 扫描（接收方识别属于自己的付款）与监管解密；
//! - [`validium`]：Private Validium 状态根提交与数据访问授权（IAM）；
//! - [`compliance`]：合规重算（凭证 ↔ 策略 ↔ 召回联动，写路径）与
//!   只读合规检查 / 必需凭证查询。
//!
//! 与 handlers 的边界：shielded_transfer / issue / revoke credential 是
//! **写动作**走 IntentEngine 管道（compliance 重算在 handler 事务内被
//! 复用）；扫描/解密/合规查询是纯读，validium root 提交是系统级结算动作
//! （`SubmitStateRoot` 免能力，Phase1 由服务层直调），授权是 IAM 操作
//! （无对应 IntentAction，Phase2 扩展）。

pub mod compliance;
pub mod shielded;
pub mod validium;
