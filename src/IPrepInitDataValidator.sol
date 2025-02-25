// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPrepInitDataValidator {
    function validatePREPInitData(bytes calldata prepInitData) external view returns (bytes calldata);
}
