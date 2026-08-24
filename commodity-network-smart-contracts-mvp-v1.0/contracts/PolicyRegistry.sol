// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract PolicyRegistry is AccessControl {
    bytes32 public constant POLICY_ADMIN_ROLE = keccak256("POLICY_ADMIN_ROLE");

    struct Policy {
        bytes32 policyId;
        uint64 version;
        bytes32 authorityDid;
        bytes32 jurisdiction;
        bytes32 productType;
        bytes32 policyHash;
        uint64 effectiveAt;
        uint64 expiresAt;
        bool active;
    }

    mapping(bytes32 => Policy) public policies;

    event PolicyRegistered(
        bytes32 indexed policyId,
        uint64 version,
        bytes32 indexed authorityDid,
        bytes32 policyHash
    );

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(POLICY_ADMIN_ROLE, admin);
    }

    function registerPolicy(
        bytes32 policyId,
        uint64 version,
        bytes32 authorityDid,
        bytes32 jurisdiction,
        bytes32 productType,
        bytes32 policyHash,
        uint64 effectiveAt,
        uint64 expiresAt
    ) external onlyRole(POLICY_ADMIN_ROLE) {
        require(policies[policyId].policyId == bytes32(0), "policy exists");
        policies[policyId] = Policy(
            policyId,
            version,
            authorityDid,
            jurisdiction,
            productType,
            policyHash,
            effectiveAt,
            expiresAt,
            true
        );
        emit PolicyRegistered(policyId, version, authorityDid, policyHash);
    }

    function isActive(bytes32 policyId) public view returns (bool) {
        Policy memory p = policies[policyId];
        if (!p.active) return false;
        if (block.timestamp < p.effectiveAt) return false;
        if (p.expiresAt != 0 && block.timestamp >= p.expiresAt) return false;
        return true;
    }
}
