// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract CredentialRegistry is AccessControl {
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    enum Status { NONE, ACTIVE, REVOKED, EXPIRED }

    struct Credential {
        bytes32 credentialHash;
        bytes32 schemaId;
        bytes32 issuerDid;
        bytes32 subjectDid;
        uint64 issuedAt;
        uint64 expiresAt;
        Status status;
    }

    mapping(bytes32 => Credential) public credentials;

    event CredentialIssued(
        bytes32 indexed credentialId,
        bytes32 indexed issuerDid,
        bytes32 indexed subjectDid,
        bytes32 schemaId
    );
    event CredentialRevoked(bytes32 indexed credentialId);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ISSUER_ROLE, admin);
    }

    function issue(
        bytes32 credentialId,
        bytes32 credentialHash,
        bytes32 schemaId,
        bytes32 issuerDid,
        bytes32 subjectDid,
        uint64 expiresAt
    ) external onlyRole(ISSUER_ROLE) {
        require(credentials[credentialId].status == Status.NONE, "credential exists");
        require(credentialHash != bytes32(0), "zero hash");

        credentials[credentialId] = Credential({
            credentialHash: credentialHash,
            schemaId: schemaId,
            issuerDid: issuerDid,
            subjectDid: subjectDid,
            issuedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            status: Status.ACTIVE
        });

        emit CredentialIssued(credentialId, issuerDid, subjectDid, schemaId);
    }

    function revoke(bytes32 credentialId) external onlyRole(ISSUER_ROLE) {
        require(credentials[credentialId].status == Status.ACTIVE, "not active");
        credentials[credentialId].status = Status.REVOKED;
        emit CredentialRevoked(credentialId);
    }

    function isValid(bytes32 credentialId) public view returns (bool) {
        Credential memory c = credentials[credentialId];
        if (c.status != Status.ACTIVE) return false;
        if (c.expiresAt != 0 && block.timestamp >= c.expiresAt) return false;
        return true;
    }
}
