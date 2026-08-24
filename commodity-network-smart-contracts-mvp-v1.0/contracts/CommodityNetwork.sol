// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IdentityRegistry} from "./IdentityRegistry.sol";
import {CredentialRegistry} from "./CredentialRegistry.sol";
import {BatchRegistry} from "./BatchRegistry.sol";
import {AssetRegistry} from "./AssetRegistry.sol";
import {OwnershipRegistry} from "./OwnershipRegistry.sol";
import {LifecycleRegistry} from "./LifecycleRegistry.sol";
import {PolicyRegistry} from "./PolicyRegistry.sol";
import {ProofRegistry} from "./ProofRegistry.sol";
import {ComplianceRegistry} from "./ComplianceRegistry.sol";

contract CommodityNetwork is AccessControl, ReentrancyGuard {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    IdentityRegistry public immutable identity;
    CredentialRegistry public immutable credentials;
    BatchRegistry public immutable batches;
    AssetRegistry public immutable assets;
    OwnershipRegistry public immutable ownership;
    LifecycleRegistry public immutable lifecycle;
    PolicyRegistry public immutable policies;
    ProofRegistry public immutable proofs;
    ComplianceRegistry public immutable compliance;

    event ProductIntentExecuted(
        bytes32 indexed intentId,
        bytes32 indexed action,
        bytes32 indexed resourceId,
        bytes32 actorDid
    );

    constructor(
        address admin,
        address identity_,
        address credentials_,
        address batches_,
        address assets_,
        address ownership_,
        address lifecycle_,
        address policies_,
        address proofs_,
        address compliance_
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);

        identity = IdentityRegistry(identity_);
        credentials = CredentialRegistry(credentials_);
        batches = BatchRegistry(batches_);
        assets = AssetRegistry(assets_);
        ownership = OwnershipRegistry(ownership_);
        lifecycle = LifecycleRegistry(lifecycle_);
        policies = PolicyRegistry(policies_);
        proofs = ProofRegistry(proofs_);
        compliance = ComplianceRegistry(compliance_);
    }

    function executeTransfer(
        bytes32 intentId,
        bytes32 assetId,
        bytes32 actorDid,
        bytes32 toDid,
        bool c2c
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        ownership.transfer(assetId, toDid, c2c);
        lifecycle.setState(
            assetId,
            c2c
                ? LifecycleRegistry.State.RESOLD
                : LifecycleRegistry.State.OWNED,
            keccak256("TRANSFER")
        );

        emit ProductIntentExecuted(
            intentId,
            keccak256("TRANSFER_PRODUCT"),
            assetId,
            actorDid
        );
    }

    function executeCompliance(
        bytes32 intentId,
        bytes32 resultId,
        bytes32 productRef,
        bytes32 regulatoryDomain,
        bytes32 policyId,
        uint64 policyVersion,
        bytes32 proofId,
        bool compliant,
        bytes32 actorDid
    ) external onlyRole(OPERATOR_ROLE) {
        require(policies.isActive(policyId), "policy inactive");
        require(proofs.isVerified(proofId), "proof invalid");

        compliance.recordCompliance(
            resultId,
            productRef,
            regulatoryDomain,
            policyId,
            policyVersion,
            proofId,
            compliant
        );

        emit ProductIntentExecuted(
            intentId,
            keccak256("COMPLIANCE_CHECK"),
            productRef,
            actorDid
        );
    }
}
