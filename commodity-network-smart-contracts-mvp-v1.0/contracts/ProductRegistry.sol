// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract ProductRegistry is AccessControl {
    bytes32 public constant PRODUCT_ADMIN_ROLE = keccak256("PRODUCT_ADMIN_ROLE");

    struct ProductType {
        bytes32 productId;
        bytes32 category;
        bytes32 metadataHash;
        bool active;
    }

    mapping(bytes32 => ProductType) public products;

    event ProductTypeRegistered(bytes32 indexed productId, bytes32 category, bytes32 metadataHash);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PRODUCT_ADMIN_ROLE, admin);
    }

    function registerProductType(
        bytes32 productId,
        bytes32 category,
        bytes32 metadataHash
    ) external onlyRole(PRODUCT_ADMIN_ROLE) {
        require(products[productId].productId == bytes32(0), "exists");
        products[productId] = ProductType(productId, category, metadataHash, true);
        emit ProductTypeRegistered(productId, category, metadataHash);
    }
}
