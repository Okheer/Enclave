// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

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
    function verify_with_expected_signer(
        bytes32 intent_hash,
        bytes calldata attestation_data,
        bytes calldata tee_sig,
        address expected_signer
    ) external returns (bool);
}