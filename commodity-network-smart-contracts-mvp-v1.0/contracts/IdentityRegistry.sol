// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

contract IdentityRegistry is AccessControl, Pausable {
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    struct Identity {
        bytes32 did;
        bytes32 subjectType;
        bool active;
        uint64 registeredAt;
    }

    mapping(address => Identity) private _identities;
    mapping(bytes32 => address) public controllerOf;

    event IdentityRegistered(address indexed account, bytes32 indexed did, bytes32 subjectType);
    event IdentityStatusChanged(address indexed account, bool active);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(REGISTRAR_ROLE, admin);
    }

    function registerIdentity(
        address account,
        bytes32 did,
        bytes32 subjectType
    ) external onlyRole(REGISTRAR_ROLE) whenNotPaused {
        require(account != address(0), "zero account");
        require(did != bytes32(0), "zero did");
        require(_identities[account].did == bytes32(0), "already registered");
        require(controllerOf[did] == address(0), "did exists");

        _identities[account] = Identity(did, subjectType, true, uint64(block.timestamp));
        controllerOf[did] = account;
        emit IdentityRegistered(account, did, subjectType);
    }

    function setActive(address account, bool active)
        external
        onlyRole(REGISTRAR_ROLE)
    {
        require(_identities[account].did != bytes32(0), "unknown identity");
        _identities[account].active = active;
        emit IdentityStatusChanged(account, active);
    }

    function isActive(address account) external view returns (bool) {
        return _identities[account].active;
    }

    function didOf(address account) external view returns (bytes32) {
        return _identities[account].did;
    }

    function getIdentity(address account) external view returns (Identity memory) {
        return _identities[account];
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) { _unpause(); }
}
