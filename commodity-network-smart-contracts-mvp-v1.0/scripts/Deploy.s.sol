// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
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

contract Deploy is Script {
    function run() external returns (CommodityNetwork network) {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(pk);

        vm.startBroadcast(pk);

        IdentityRegistry identity = new IdentityRegistry(deployer);
        CredentialRegistry credentials = new CredentialRegistry(deployer);
        ProductRegistry products = new ProductRegistry(deployer);
        BatchRegistry batches = new BatchRegistry(deployer);
        AssetRegistry assets = new AssetRegistry(deployer);
        OwnershipRegistry ownership = new OwnershipRegistry(deployer);
        LifecycleRegistry lifecycle = new LifecycleRegistry(deployer);
        PolicyRegistry policies = new PolicyRegistry(deployer);
        ProofRegistry proofs = new ProofRegistry(deployer);
        ComplianceRegistry compliance = new ComplianceRegistry(deployer);

        network = new CommodityNetwork(
            deployer,
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

        vm.stopBroadcast();
    }
}
