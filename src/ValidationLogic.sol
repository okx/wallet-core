// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import {IValidation} from "./interfaces/IValidation.sol";
import {IStorage} from "./interfaces/IStorage.sol";

import {WalletCoreBase} from "./base/WalletCoreBase.sol";
import {WalletCoreLib} from "./lib/WalletCoreLib.sol";
import {Call} from "./Types.sol";
import {Errors} from "./lib/Errors.sol";

abstract contract ValidationLogic is IValidation, WalletCoreBase {
    using Clones for address;

    bytes32 private constant CALLS_TYPEHASH =
        keccak256("Calls(address wallet,uint256 nonce,bytes32[] calls)");
    bytes32 private constant CALL_TYPEHASH =
        keccak256("Call(address target,uint256 value,bytes data)");

    /**
     * @notice Modifier that validates a transaction using the specified validator
     * @dev Reads and updates the nonce from storage before validation
     * @param calls Array of calls to be validated
     * @param validator Address of the validator contract
     * @param validationData The validation data (signature for ECDSA, custom data for other validators)
     */
    modifier onlyValidator(
        Call[] calldata calls,
        address validator,
        bytes calldata validationData
    ) {
        uint256 nonce = getMainStorage().readAndUpdateNonce(validator);
        _validateCall(nonce, calls, validator, validationData);
        _;
    }

    /**
     * @notice Adds a new validator contract to the wallet
     * @param validatorImpl The implementation address of the validator contract to be registered
     * @param immutableArgs Initialization data for the validator contract
     */
    function _addValidator(
        address validatorImpl,
        bytes calldata immutableArgs
    ) internal {
        if (validatorImpl.code.length == 0)
            revert Errors.InvalidValidatorImpl(validatorImpl);

        // Fix creation salt
        bytes32 salt = WalletCoreLib.VALIDATOR_SALT;

        // Deploy using deterministic address
        address createdAddress = validatorImpl
            .cloneDeterministicWithImmutableArgs(immutableArgs, salt);

        getMainStorage().setValidatorStatus(createdAddress, true);

        // Initialize the validator
        emit ValidatorAdded(createdAddress);
    }

    /**
     * @notice Implements EIP-1271 signature validation standard
     * @dev Validates signatures by checking both the validator's signature and its authenticity
     * @dev The signature is bound to this wallet's address and the current chain ID
     * @param validator The address of the validator contract
     * @param _hash The hash of the data to be validated
     * @param signature ABI encoded (validator, signature) pair where:
     *        - validator: address of the validator contract
     *        - signature: the actual signature or validation data
     * @return bytes4 Returns MAGIC_VALUE (0x1626ba7e) if valid, INVALID_VALUE (0xffffffff) if invalid
     * @custom:security Verifies the validator is legitimate by checking its deterministic deployment
     */
    function isValidSignature(
        address validator,
        bytes32 _hash,
        bytes calldata signature
    ) internal view returns (bool) {
        try getMainStorage().validateValidator(validator) {} catch {
            return false;
        }

        bytes32 boundHash = keccak256(
            abi.encode(bytes32(block.chainid), address(this), _hash)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", boundHash));

        return WalletCoreLib.validate(validator, digest, signature);
    }

    /**
     * @notice Generates an EIP-712 compliant typed data hash for transaction validation
     * @dev Combines the message hash with the domain separator using EIP-712 standard
     * @param nonce Current transaction nonce used to prevent replay attacks
     * @param calls Array of calls to be validated
     * @return bytes32 The EIP-712 typed data hash ready for signing
     */
    function getValidationTypedHash(
        uint256 nonce,
        Call[] calldata calls
    ) public view returns (bytes32) {
        return _hashTypedDataV4(_getValidationHash(nonce, calls));
    }

    /**
     * @notice Computes the deterministic address of a validator
     * @dev Uses the validator implementation and signer to calculate the expected address
     * @param validatorImpl The implementation contract address for the validator
     * @param immutableArgs The initialization code of the validator
     * @return address The predicted validator contract address
     */
    function computeValidatorAddress(
        address validatorImpl,
        bytes calldata immutableArgs
    ) public view returns (address) {
        return
            WalletCoreLib._computeValidatorAddress(
                validatorImpl,
                immutableArgs,
                WalletCoreLib.VALIDATOR_SALT,
                address(this)
            );
    }

    /**
     * @notice Internal function to validate a transaction using EIP-712 typed data
     * @dev Generates typed data hash and validates it using the specified validator
     * @param nonce Current transaction nonce from storage
     * @param calls Array of calls to be validated
     * @param validator Address of the validator contract
     * @param validationData The validation data (signature for ECDSA, custom data for other validators)
     */
    function _validateCall(
        uint256 nonce,
        Call[] calldata calls,
        address validator,
        bytes calldata validationData
    ) internal view {
        bytes32 typedDataHash = getValidationTypedHash(nonce, calls);
        bool isValid = WalletCoreLib.validate(
            validator,
            typedDataHash,
            validationData
        );
        if (!isValid) revert Errors.InvalidSignature();
    }

    /**
     * @notice Creates a hash of the transaction data for validation
     * @dev Combines nonce and calls into a single hash using EIP-712 encoding
     * @param nonce Transaction nonce for replay protection
     * @param calls Array of calls to execute
     * @return bytes32 Hash of the transaction data
     */
    function _getValidationHash(
        uint256 nonce,
        Call[] calldata calls
    ) internal view returns (bytes32) {
        bytes32[] memory callHashes = new bytes32[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            callHashes[i] = keccak256(
                abi.encode(
                    CALL_TYPEHASH,
                    calls[i].target,
                    calls[i].value,
                    keccak256(calls[i].data)
                )
            );
        }

        return
            keccak256(
                abi.encode(
                    CALLS_TYPEHASH,
                    _walletImplementation(),
                    nonce,
                    keccak256(abi.encodePacked(callHashes))
                )
            );
    }
}
