//! sol! 绑定：`contracts-ext` 两合约的 ABI 接口（内联声明，Task 26）。
//!
//! **不引用 .sol 文件路径**——合约 import OZ v5 AccessControl，本仓无
//! Foundry / OZ 依赖，走文件路径会引入编译依赖。以下接口与
//! `contracts-ext/ShieldedRegistry.sol`、`contracts-ext/StateAnchor.sol`
//! 的函数签名**一一对应，字段顺序不得漂移**（合约侧改动须同步此处）。
//!
//! 绑定的是 interface（不含事件/权限逻辑），调用侧以 `onlyRole` 操作员
//! 身份发交易（见 provider.rs 的 OPERATOR_KEY）。

use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IShieldedRegistry {
        function commitAndSpend(bytes32 nf, bytes32 commitment, bytes encryptedExtra) external;
        function spend(bytes32 nf) external;
        function commit(bytes32 commitment, bytes encryptedExtra) external;
        function isNullifierSpent(bytes32 nf) external view returns (bool);
        function isCommitmentPresent(bytes32 commitment) external view returns (bool);
    }
}

sol! {
    #[sol(rpc)]
    interface IStateAnchor {
        function commitRoot(bytes32 root, string batchRef) external;
    }
}
