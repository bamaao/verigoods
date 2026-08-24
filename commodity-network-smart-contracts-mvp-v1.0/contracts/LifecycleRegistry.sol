// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract LifecycleRegistry is AccessControl {
    bytes32 public constant LIFECYCLE_OPERATOR_ROLE = keccak256("LIFECYCLE_OPERATOR_ROLE");

    enum State {
        NONE,
        CREATED,
        PRODUCED,
        INSPECTED,
        IN_TRANSIT,
        IN_WAREHOUSE,
        AVAILABLE,
        SOLD,
        OWNED,
        RESOLD,
        RECALLED,
        EXPIRED,
        DESTROYED
    }

    mapping(bytes32 => State) public stateOf;

    event LifecycleChanged(bytes32 indexed assetId, State from, State to, bytes32 reason);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(LIFECYCLE_OPERATOR_ROLE, admin);
    }

    function setState(
        bytes32 assetId,
        State next,
        bytes32 reason
    ) external onlyRole(LIFECYCLE_OPERATOR_ROLE) {
        State previous = stateOf[assetId];
        stateOf[assetId] = next;
        emit LifecycleChanged(assetId, previous, next, reason);
    }
}
