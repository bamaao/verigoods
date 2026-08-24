// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract ComplianceRegistry is AccessControl {
    bytes32 public constant COMPLIANCE_OPERATOR_ROLE = keccak256("COMPLIANCE_OPERATOR_ROLE");

    struct ComplianceResult {
        bytes32 productRef;
        bytes32 regulatoryDomain;
        bytes32 policyId;
        uint64 policyVersion;
        bytes32 proofId;
        bool compliant;
        uint64 checkedAt;
    }

    mapping(bytes32 => ComplianceResult) public results;

    event ComplianceRecorded(
        bytes32 indexed resultId,
        bytes32 indexed productRef,
        bytes32 indexed regulatoryDomain,
        bytes32 policyId,
        bytes32 proofId,
        bool compliant
    );

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(COMPLIANCE_OPERATOR_ROLE, admin);
    }

    function recordCompliance(
        bytes32 resultId,
        bytes32 productRef,
        bytes32 regulatoryDomain,
        bytes32 policyId,
        uint64 policyVersion,
        bytes32 proofId,
        bool compliant
    ) external onlyRole(COMPLIANCE_OPERATOR_ROLE) {
        require(results[resultId].checkedAt == 0, "result exists");

        results[resultId] = ComplianceResult(
            productRef,
            regulatoryDomain,
            policyId,
            policyVersion,
            proofId,
            compliant,
            uint64(block.timestamp)
        );

        emit ComplianceRecorded(
            resultId,
            productRef,
            regulatoryDomain,
            policyId,
            proofId,
            compliant
        );
    }
}
