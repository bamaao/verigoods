// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract OwnershipRegistry is AccessControl {
    bytes32 public constant TRANSFER_OPERATOR_ROLE = keccak256("TRANSFER_OPERATOR_ROLE");

    struct Ownership {
        bytes32 ownerDid;
        uint64 acquiredAt;
        uint64 transferCount;
        uint64 c2cCount;
    }

    mapping(bytes32 => Ownership) public ownershipOf;

    event OwnershipTransferred(
        bytes32 indexed assetId,
        bytes32 indexed fromDid,
        bytes32 indexed toDid,
        bool c2c,
        uint64 transferCount
    );

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(TRANSFER_OPERATOR_ROLE, admin);
    }

    function initializeOwner(bytes32 assetId, bytes32 ownerDid)
        external
        onlyRole(TRANSFER_OPERATOR_ROLE)
    {
        require(ownershipOf[assetId].ownerDid == bytes32(0), "owner exists");
        ownershipOf[assetId] = Ownership(ownerDid, uint64(block.timestamp), 0, 0);
    }

    function transfer(
        bytes32 assetId,
        bytes32 toDid,
        bool c2c
    ) external onlyRole(TRANSFER_OPERATOR_ROLE) {
        Ownership storage o = ownershipOf[assetId];
        require(o.ownerDid != bytes32(0), "no owner");
        require(toDid != bytes32(0) && toDid != o.ownerDid, "invalid target");

        bytes32 fromDid = o.ownerDid;
        o.ownerDid = toDid;
        o.acquiredAt = uint64(block.timestamp);
        o.transferCount += 1;
        if (c2c) o.c2cCount += 1;

        emit OwnershipTransferred(assetId, fromDid, toDid, c2c, o.transferCount);
    }
}
