// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract AssetRegistry is AccessControl {
    bytes32 public constant ASSET_OPERATOR_ROLE = keccak256("ASSET_OPERATOR_ROLE");

    struct Asset {
        bytes32 assetId;
        bytes32 productId;
        bytes32 manufacturerDid;
        bytes32 authenticityCommitment;
        uint64 createdAt;
        bool active;
    }

    mapping(bytes32 => Asset) public assets;

    event AssetCreated(bytes32 indexed assetId, bytes32 indexed productId, bytes32 manufacturerDid);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ASSET_OPERATOR_ROLE, admin);
    }

    function createAsset(
        bytes32 assetId,
        bytes32 productId,
        bytes32 manufacturerDid,
        bytes32 authenticityCommitment
    ) external onlyRole(ASSET_OPERATOR_ROLE) {
        require(assets[assetId].assetId == bytes32(0), "asset exists");
        assets[assetId] = Asset(
            assetId,
            productId,
            manufacturerDid,
            authenticityCommitment,
            uint64(block.timestamp),
            true
        );
        emit AssetCreated(assetId, productId, manufacturerDid);
    }
}
