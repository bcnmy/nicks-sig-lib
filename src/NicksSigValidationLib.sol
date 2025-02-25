// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ECDSA } from "solady/utils/ECDSA.sol";

// TODO: remove this
import "forge-std/console2.sol";

library NicksSigValidationLib {

    /// @notice Error thrown when an invalid nicks method data is detected
    error InvalidNicksMethodData(bytes32 authHash, bytes32 initDataHash, bytes signature);

    /// @param sPattern The pattern of the s value in the signature. 20 MSB are magic value, 12 LSB are 0s.
    function validateNicksSig(bytes calldata data, bytes32 sPattern) internal view returns (bytes calldata initData) {
        bytes32 r;
        bytes32 s;
        bytes32 authHash;
        bytes calldata signature;
        assembly {
            if lt(data.length, 0x61) {
                mstore(0x0, 0xaed59595) // NotInitializable()
                revert(0x1c, 0x04)
            }
            authHash := calldataload(data.offset)
            let p := calldataload(add(data.offset, 0x20))
            let u := add(data.offset, p)
            signature.offset := add(u, 0x20)
            signature.length := calldataload(u)
            let o:= calldataload(add(data.offset, 0x40))
            u := add(data.offset, o)
            initData.offset := add(u, 0x20)
            initData.length := calldataload(u)

            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 0x20))
        }
        
        // check that signature (r value) is based on the hash of the initData provided 
        bytes32 initDataHash = keccak256(initData);
        require(r == initDataHash, InvalidNicksMethodData(authHash, initDataHash, signature));

        // check that signature (s value) matches the expected pattern of having 0s in the 20 leftmost bytes
        require(s & 0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000 == sPattern);
        
        // check auth hash signed by address(this)
        // we just use authHash provided in the `data` instead of recomputing it
        // because it is computationally unlikely to find another hash that 
        // combined with another `r` (which means another initdata) 
        // and another `s` that matches the pattern of having 0s in the 20 leftmost bytes
        // would result in the same recovered signer (address(this)).
        address signer = ECDSA.recover(authHash, signature);
        // TODO: remove this
        console2.log("signer", signer);
        console2.log("address(this)", address(this));
        assembly {
            if iszero(eq(signer, caller())) {
                mstore(0x0, 0xaed59595) // NotInitializable()
                revert(0x1c, 0x04)
            }
        }
    }
    
}
