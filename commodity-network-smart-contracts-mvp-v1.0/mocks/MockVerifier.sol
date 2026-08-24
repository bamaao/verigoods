// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProofVerifier} from "../contracts/ProofRegistry.sol";

contract MockVerifier is IProofVerifier {
    bool public result;

    constructor(bool result_) {
        result = result_;
    }

    function setResult(bool result_) external {
        result = result_;
    }

    function verify(bytes calldata, bytes32[] calldata)
        external
        view
        returns (bool)
    {
        return result;
    }
}
