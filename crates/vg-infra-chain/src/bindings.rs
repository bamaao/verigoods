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

#[cfg(test)]
mod tests {
    //! ABI selector 锁定测试：**改合约（contracts-ext/*.sol）必同步上方
    //! sol! 声明，此测试拦截签名漂移**——selector = keccak256(签名)[:4]，
    //! 期望值独立用 alloy keccak256 手算，与 sol! 生成的 `SELECTOR` 常量
    //! 逐一比对。纯计算、不 ignore、无需网络。
    use super::*;
    use alloy::primitives::keccak256;
    use alloy::sol_types::SolCall;

    /// keccak(规范签名)[:4] —— 独立于 sol! 代码生成的期望值来源。
    fn expected_selector(signature: &str) -> [u8; 4] {
        let hash = keccak256(signature.as_bytes());
        hash.0[..4]
            .try_into()
            .expect("keccak256 输出恒为 32 字节，前 4 字节切片必成功")
    }

    #[test]
    fn shielded_registry_selectors_match_contract_signatures() {
        assert_eq!(
            IShieldedRegistry::commitAndSpendCall::SELECTOR,
            expected_selector("commitAndSpend(bytes32,bytes32,bytes)")
        );
        assert_eq!(
            IShieldedRegistry::spendCall::SELECTOR,
            expected_selector("spend(bytes32)")
        );
        assert_eq!(
            IShieldedRegistry::commitCall::SELECTOR,
            expected_selector("commit(bytes32,bytes)")
        );
        assert_eq!(
            IShieldedRegistry::isNullifierSpentCall::SELECTOR,
            expected_selector("isNullifierSpent(bytes32)")
        );
        assert_eq!(
            IShieldedRegistry::isCommitmentPresentCall::SELECTOR,
            expected_selector("isCommitmentPresent(bytes32)")
        );
    }

    #[test]
    fn state_anchor_selector_matches_contract_signature() {
        assert_eq!(
            IStateAnchor::commitRootCall::SELECTOR,
            expected_selector("commitRoot(bytes32,string)")
        );
    }
}
