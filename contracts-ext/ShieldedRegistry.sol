// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title VeriGoods ShieldedRegistry —— Shielded 交易账本合约
/// @notice 记录 note commitment 与已消费 nullifier（防双花），以及监管可解的
///         加密附加数据密文（仅入事件，不在链上存储密文本体）。
///
/// 部署目标：Polygon CDK（kurtosis-cdk 本地环境 / CDK 测试网）。
/// OZ v5 依赖（@openzeppelin/contracts）由部署环境提供。
///
/// ⚠ 本仓库不安装 Foundry，本合约不在本仓编译/测试——编译部署由用户在
/// WSL kurtosis-cdk 环境完成（Task 27 约定：只开发不本地测）。
///
/// 与 Rust 侧 vg-infra-chain 的 ABI 对应（bindings.rs 内联 sol! 接口）：
/// commitAndSpend / spend / commit / isNullifierSpent / isCommitmentPresent，
/// 字段顺序不得漂移。
contract ShieldedRegistry is AccessControl {
    bytes32 public constant SHIELDED_OPERATOR_ROLE = keccak256("SHIELDED_OPERATOR_ROLE");

    /// @dev 已消费 nullifier 集合（true = 已花费）。
    mapping(bytes32 => bool) public nullifiers;
    /// @dev 已上链 note commitment 集合（true = 已存在）。
    mapping(bytes32 => bool) public commitments;

    /// @notice nullifier 花费 + commitment 落账（原子组合入口）
    event NoteSpent(bytes32 indexed nf, bytes32 commitment);
    /// @notice commitment 落账（携带监管可解密文）
    event NoteCommitted(bytes32 indexed commitment, bytes encryptedExtra);
    /// @dev 仅 commitment 落账（独立 commit 入口）时复用 NoteCommitted（extra 为空）。
    /// @dev 仅 nullifier 花费（独立 spend 入口）时复用 NoteSpent（commitment 为零）。

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(SHIELDED_OPERATOR_ROLE, admin);
    }

    /// @notice 原子组合入口：花费 nf 并落账 commitment（供未来 spend 电路直调）
    function commitAndSpend(
        bytes32 nf,
        bytes32 commitment,
        bytes calldata encryptedExtra
    ) external onlyRole(SHIELDED_OPERATOR_ROLE) {
        require(!nullifiers[nf], "nf spent");
        require(!commitments[commitment], "commitment exists");
        nullifiers[nf] = true;
        commitments[commitment] = true;
        emit NoteSpent(nf, commitment);
        emit NoteCommitted(commitment, encryptedExtra);
    }

    /// @notice 独立花费入口（适配器 N→C→E 顺序契约的拆步 fallback 用）
    function spend(bytes32 nf) external onlyRole(SHIELDED_OPERATOR_ROLE) {
        require(!nullifiers[nf], "nf spent");
        nullifiers[nf] = true;
        emit NoteSpent(nf, bytes32(0));
    }

    /// @notice 独立落账入口（无 pending nf 的 commitment 场景，extra 为空）
    function commit(bytes32 commitment, bytes calldata encryptedExtra)
        external
        onlyRole(SHIELDED_OPERATOR_ROLE)
    {
        require(!commitments[commitment], "commitment exists");
        commitments[commitment] = true;
        emit NoteCommitted(commitment, encryptedExtra);
    }

    /// @notice 便捷视图（与 public mapping 等价）
    function isNullifierSpent(bytes32 nf) external view returns (bool) {
        return nullifiers[nf];
    }

    /// @notice 便捷视图（与 public mapping 等价）
    function isCommitmentPresent(bytes32 commitment) external view returns (bool) {
        return commitments[commitment];
    }
}
