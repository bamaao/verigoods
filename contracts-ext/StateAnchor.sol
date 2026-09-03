// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title VeriGoods StateAnchor —— Private Validium 状态根锚定合约
/// @notice 批量结算：将 validium 状态根提交上链（L1 结算）。
///
/// 幂等语义：重复提交同一 root **不 revert**（接受并再发事件），与
/// vg-infra-pg InProcessLedger 的 state_root 语义对齐（无唯一索引，
/// 重复提交各自记账）。root 为零值拒绝（防止空根误提交）。
///
/// 部署目标：Polygon CDK（kurtosis-cdk 本地环境 / CDK 测试网）。
/// OZ v5 依赖（@openzeppelin/contracts）由部署环境提供。
///
/// ⚠ 本仓库不安装 Foundry，本合约不在本仓编译/测试——编译部署由用户在
/// WSL kurtosis-cdk 环境完成（Task 27 约定：只开发不本地测）。
contract StateAnchor is AccessControl {
    bytes32 public constant STATE_ANCHOR_OPERATOR_ROLE = keccak256("STATE_ANCHOR_OPERATOR_ROLE");

    /// @dev 已提交状态根集合（对账用视图）。
    mapping(bytes32 => bool) public roots;

    /// @notice 状态根提交（root indexed，便于日志过滤）
    event StateRootCommitted(bytes32 indexed root, string batchRef);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(STATE_ANCHOR_OPERATOR_ROLE, admin);
    }

    /// @notice 提交状态根；重复 root 幂等接受（不 revert），零值拒绝
    function commitRoot(bytes32 root, string calldata batchRef)
        external
        onlyRole(STATE_ANCHOR_OPERATOR_ROLE)
    {
        require(root != bytes32(0), "zero root");
        roots[root] = true;
        emit StateRootCommitted(root, batchRef);
    }
}
