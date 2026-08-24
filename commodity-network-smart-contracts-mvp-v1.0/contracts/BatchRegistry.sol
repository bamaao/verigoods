// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract BatchRegistry is AccessControl {
    bytes32 public constant BATCH_OPERATOR_ROLE = keccak256("BATCH_OPERATOR_ROLE");

    struct Batch {
        bytes32 batchId;
        bytes32 productId;
        bytes32 producerDid;
        uint256 quantity;
        bytes32 unit;
        uint64 productionTime;
        bytes32 metadataCommitment;
        bool active;
    }

    mapping(bytes32 => Batch) public batches;
    mapping(bytes32 => bytes32[]) public childrenOf;
    mapping(bytes32 => bytes32[]) public parentsOf;

    event BatchCreated(bytes32 indexed batchId, bytes32 indexed productId, bytes32 producerDid, uint256 quantity);
    event BatchSplit(bytes32 indexed parent, bytes32[] children);
    event BatchMerged(bytes32[] parents, bytes32 indexed child);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(BATCH_OPERATOR_ROLE, admin);
    }

    function createBatch(
        bytes32 batchId,
        bytes32 productId,
        bytes32 producerDid,
        uint256 quantity,
        bytes32 unit,
        uint64 productionTime,
        bytes32 metadataCommitment
    ) external onlyRole(BATCH_OPERATOR_ROLE) {
        require(batches[batchId].batchId == bytes32(0), "batch exists");
        require(quantity > 0, "zero quantity");
        batches[batchId] = Batch(
            batchId,
            productId,
            producerDid,
            quantity,
            unit,
            productionTime,
            metadataCommitment,
            true
        );
        emit BatchCreated(batchId, productId, producerDid, quantity);
    }

    function splitBatch(
        bytes32 parentId,
        bytes32[] calldata childIds,
        uint256[] calldata quantities
    ) external onlyRole(BATCH_OPERATOR_ROLE) {
        require(childIds.length == quantities.length && childIds.length > 0, "length");
        Batch storage parent = batches[parentId];
        require(parent.active, "inactive parent");

        uint256 total;
        for (uint256 i = 0; i < childIds.length; i++) {
            require(batches[childIds[i]].batchId == bytes32(0), "child exists");
            require(quantities[i] > 0, "zero child");
            total += quantities[i];

            batches[childIds[i]] = Batch(
                childIds[i],
                parent.productId,
                parent.producerDid,
                quantities[i],
                parent.unit,
                parent.productionTime,
                parent.metadataCommitment,
                true
            );
            childrenOf[parentId].push(childIds[i]);
            parentsOf[childIds[i]].push(parentId);
        }

        require(total == parent.quantity, "quantity mismatch");
        parent.active = false;
        emit BatchSplit(parentId, childIds);
    }

    function mergeBatches(
        bytes32[] calldata parentIds,
        bytes32 childId,
        uint256 quantity
    ) external onlyRole(BATCH_OPERATOR_ROLE) {
        require(parentIds.length > 0 && quantity > 0, "invalid");
        require(batches[childId].batchId == bytes32(0), "child exists");

        bytes32 productId = batches[parentIds[0]].productId;
        bytes32 producerDid = batches[parentIds[0]].producerDid;
        bytes32 unit = batches[parentIds[0]].unit;
        uint64 productionTime = batches[parentIds[0]].productionTime;
        bytes32 metadataCommitment = batches[parentIds[0]].metadataCommitment;

        uint256 total;
        for (uint256 i = 0; i < parentIds.length; i++) {
            Batch storage p = batches[parentIds[i]];
            require(p.active, "parent inactive");
            require(p.productId == productId, "product mismatch");
            total += p.quantity;
            p.active = false;
            parentsOf[childId].push(parentIds[i]);
            childrenOf[parentIds[i]].push(childId);
        }

        require(total == quantity, "quantity mismatch");

        batches[childId] = Batch(
            childId,
            productId,
            producerDid,
            quantity,
            unit,
            productionTime,
            metadataCommitment,
            true
        );

        emit BatchMerged(parentIds, childId);
    }
}
