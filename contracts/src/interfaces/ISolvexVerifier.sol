// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

/// @title ISolvexVerifier
/// @notice Interface for the SolvexVerifier Stylus/Rust contract.
/// @dev    IMPORTANT — ABI NAMING CONVENTION:
///         The Stylus SDK automatically converts Rust snake_case function names
///         to Solidity camelCase in the exported ABI. This interface MUST use
///         the camelCase names to match the deployed WASM contract's ABI.
///
///         Rust fn name                → Exported ABI selector
///         ─────────────────────────────────────────────────────
///         verify                      → verify
///         verify_with_expected_signer → verifyWithExpectedSigner
///         is_intent_settled           → isIntentSettled
///         get_last_attest_hash        → getLastAttestHash
///         get_attestation_count       → getAttestationCount
///         get_owner                   → getOwner
///
///         Parameter types must also match:
///         Rust `Bytes` (alloy_primitives) → Solidity `bytes`
///         Rust `Vec<u8>`                  → Solidity `uint8[]`  (WRONG!)
interface ISolvexVerifier {
    /// @notice Verifies a TEE attestation for an intent settlement.
    ///         The attestation must be ABI-encoded before passing to this contract.
    ///         Performs three checks: nonce guard, ECDSA signature verification, and Merkle chain continuity.
    ///         Reverts on verification failure; returns true on success.
    function verify(
        bytes32 intent_hash,
        bytes calldata attestation_data,
        bytes calldata tee_sig
    ) external returns (bool);

    /// @notice Verifies a TEE attestation and checks that the recovered signer matches expected_signer.
    ///         The attestation must be ABI-encoded before passing to this contract.
    ///         Performs same checks as verify() plus signer validation.
    ///         Reverts on verification failure; returns true on success.
    function verifyWithExpectedSigner(
        bytes32 intent_hash,
        bytes calldata attestation_data,
        bytes calldata tee_sig,
        address expected_signer,
        address expected_winner
    ) external returns (bool);

    /// @notice Checks if an intent has already been settled through this verifier.
    function isIntentSettled(bytes32 intent_hash) external view returns (bool);

    /// @notice Returns the hash of the most recent attestation (Merkle chain head).
    function getLastAttestHash() external view returns (bytes32);

    /// @notice Returns the total number of verified attestations.
    function getAttestationCount() external view returns (uint256);

    /// @notice Returns the contract owner address.
    function getOwner() external view returns (address);
}