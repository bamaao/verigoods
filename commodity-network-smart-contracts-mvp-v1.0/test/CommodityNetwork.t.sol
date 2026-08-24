// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/IdentityRegistry.sol";
import "../contracts/CredentialRegistry.sol";
import "../contracts/ProductRegistry.sol";
import "../contracts/BatchRegistry.sol";
import "../contracts/AssetRegistry.sol";
import "../contracts/OwnershipRegistry.sol";
import "../contracts/LifecycleRegistry.sol";
import "../contracts/PolicyRegistry.sol";
import "../contracts/ProofRegistry.sol";
import "../contracts/ComplianceRegistry.sol";
import "../contracts/CommodityNetwork.sol";
import "../mocks/MockVerifier.sol";

contract CommodityNetworkTest is Test {
    address admin = address(0xA11CE);
    address alice = address(0xB0B);
    address bob = address(0xC0C);

    IdentityRegistry identity;
    CredentialRegistry credentials;
    ProductRegistry products;
    BatchRegistry batches;
    AssetRegistry assets;
    OwnershipRegistry ownership;
    LifecycleRegistry lifecycle;
    PolicyRegistry policies;
    ProofRegistry proofs;
    ComplianceRegistry compliance;
    CommodityNetwork network;

    bytes32 didAlice = keccak256("did:alice");
    bytes32 didBob = keccak256("did:bob");

    function setUp() public {
        identity = new IdentityRegistry(admin);
        credentials = new CredentialRegistry(admin);
        products = new ProductRegistry(admin);
        batches = new BatchRegistry(admin);
        assets = new AssetRegistry(admin);
        ownership = new OwnershipRegistry(admin);
        lifecycle = new LifecycleRegistry(admin);
        policies = new PolicyRegistry(admin);
        proofs = new ProofRegistry(admin);
        compliance = new ComplianceRegistry(admin);

        network = new CommodityNetwork(
            admin,
            address(identity),
            address(credentials),
            address(batches),
            address(assets),
            address(ownership),
            address(lifecycle),
            address(policies),
            address(proofs),
            address(compliance)
        );
    }

    function testBatchSplit() public {
        vm.startPrank(admin);

        bytes32 product = keccak256("PORK");
        bytes32 parent = keccak256("BATCH-001");
        bytes32 child1 = keccak256("BATCH-001-A");
        bytes32 child2 = keccak256("BATCH-001-B");

        batches.createBatch(
            parent,
            product,
            didAlice,
            1000,
            keccak256("KG"),
            uint64(block.timestamp),
            keccak256("metadata")
        );

        bytes32[] memory ids = new bytes32[](2);
        ids[0] = child1;
        ids[1] = child2;

        uint256[] memory qs = new uint256[](2);
        qs[0] = 400;
        qs[1] = 600;

        batches.splitBatch(parent, ids, qs);

        assertFalse(batches.batches(parent).active);
        assertEq(batches.batches(child1).quantity, 400);
        assertEq(batches.batches(child2).quantity, 600);

        vm.stopPrank();
    }

    function testOwnershipTransferAndC2C() public {
        vm.startPrank(admin);

        bytes32 assetId = keccak256("ASSET-001");

        ownership.initializeOwner(assetId, didAlice);
        ownership.transfer(assetId, didBob, true);

        (bytes32 ownerDid, , uint64 transferCount, uint64 c2cCount) =
            ownership.ownershipOf(assetId);

        assertEq(ownerDid, didBob);
        assertEq(transferCount, 1);
        assertEq(c2cCount, 1);

        vm.stopPrank();
    }

    function testCredentialIssueAndRevoke() public {
        vm.startPrank(admin);

        bytes32 credentialId = keccak256("VC-001");

        credentials.issue(
            credentialId,
            keccak256("credential-body"),
            keccak256("FoodSafetyCredential"),
            keccak256("did:regulator"),
            didAlice,
            0
        );

        assertTrue(credentials.isValid(credentialId));

        credentials.revoke(credentialId);
        assertFalse(credentials.isValid(credentialId));

        vm.stopPrank();
    }

    function testComplianceWithProof() public {
        vm.startPrank(admin);

        bytes32 circuitId = keccak256("COLDCHAIN_V1");
        MockVerifier verifier = new MockVerifier(true);
        proofs.setVerifier(circuitId, address(verifier));

        bytes32 proofId = keccak256("PROOF-001");
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = keccak256("statement");

        bool verified = proofs.recordProof(
            proofId,
            circuitId,
            keccak256("statement"),
            hex"1234",
            inputs
        );

        assertTrue(verified);

        bytes32 policyId = keccak256("POLICY-FOOD-V1");
        policies.registerPolicy(
            policyId,
            1,
            keccak256("did:regulator"),
            keccak256("JP"),
            keccak256("FOOD"),
            keccak256("policy-body"),
            uint64(block.timestamp - 1),
            0
        );

        bytes32 resultId = keccak256("RESULT-001");
        compliance.recordCompliance(
            resultId,
            keccak256("BATCH-001"),
            keccak256("FOOD-SAFETY"),
            policyId,
            1,
            proofId,
            true
        );

        assertTrue(compliance.results(resultId).compliant);

        vm.stopPrank();
    }
}
