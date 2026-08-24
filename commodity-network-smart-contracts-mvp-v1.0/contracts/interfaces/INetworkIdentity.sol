// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface INetworkIdentity {
    function isActive(address account) external view returns (bool);
    function didOf(address account) external view returns (bytes32);
}
