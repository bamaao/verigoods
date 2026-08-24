// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

interface IProofVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        view
        returns (bool);
}

contract ProofRegistry is AccessControl {
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");
    bytes32 public constant VERIFIER_ADMIN_ROLE = keccak256("VERIFIER_ADMIN_ROLE");

    struct ProofRecord {
        bytes32 proofId;
        bytes32 circuitId;
        bytes32 proofHash;
        bytes32 statementHash;
        uint64 createdAt;
        bool verified;
    }

    mapping(bytes32 => ProofRecord) public proofs;
    mapping(bytes32 => address) public verifierOf;

    event VerifierSet(bytes32 indexed circuitId, address verifier);
    event ProofRecorded(bytes32 indexed proofId, bytes32 indexed circuitId, bytes32 statementHash, bool verified);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PROVER_ROLE, admin);
        _grantRole(VERIFIER_ADMIN_ROLE, admin);
    }

    function setVerifier(bytes32 circuitId, address verifier)
        external
        onlyRole(VERIFIER_ADMIN_ROLE)
    {
        verifierOf[circuitId] = verifier;
        emit VerifierSet(circuitId, verifier);
    }

    function recordProof(
        bytes32 proofId,
        bytes32 circuitId,
        bytes32 statementHash,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external onlyRole(PROVER_ROLE) returns (bool verified) {
        require(proofs[proofId].proofId == bytes32(0), "proof exists");

        address verifier = verifierOf[circuitId];
        require(verifier != address(0), "verifier missing");

        verified = IProofVerifier(verifier).verify(proof, publicInputs);

        proofs[proofId] = ProofRecord(
            proofId,
            circuitId,
            keccak256(proof),
            statementHash,
            uint64(block.timestamp),
            verified
        );

        emit ProofRecorded(proofId, circuitId, statementHash, verified);
    }

    function isVerified(bytes32 proofId) external view returns (bool) {
        return proofs[proofId].verified;
    }
}
