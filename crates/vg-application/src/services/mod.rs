//! Task 21 应用服务：隐私侧读/结算用例（不走 intent 管道或仅读）。
//!
//! - [`shielded`]：Note 扫描（接收方识别属于自己的付款）与监管解密；
//! - [`validium`]：Private Validium 状态根提交与数据访问授权（IAM）。
//!
//! 与 handlers 的边界：shielded_transfer 是**写动作**走 IntentEngine 管道；
//! 扫描/解密是纯读，validium root 提交是系统级结算动作
//! （`SubmitStateRoot` 免能力，Phase1 由服务层直调），授权是 IAM 操作
//! （无对应 IntentAction，Phase2 扩展）。

pub mod shielded;
pub mod validium;
