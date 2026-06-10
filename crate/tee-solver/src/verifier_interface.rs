use crate::attestation::Attestation;
use crate::error::{TeeError, Result};
use crate::types::Intent;
use serde::{Deserialize, Serialize};
use alloy_primitives::Address;
use std::sync::Arc;
use tokio::sync::RwLock;
use reqwest::Client as HttpClient;
use sha3::{Digest, Keccak256};

/// Interface for communication with P2's SolvexVerifier (Stylus/Rust contract on Arbitrum)
/// This module encapsulates the protocol for sending attestations to onchain verification
pub struct VerifierInterface {
    /// Verifier contract address on Arbitrum
    verifier_address: Address,
    /// Settlement contract address
    settlement_address: Address,
    /// Arbitrum RPC endpoint for contract calls
    rpc_endpoint: String,
    /// HTTP client for RPC communication
    http_client: HttpClient,
    /// Pending verifications awaiting proof
    pending_verifications: Arc<RwLock<Vec<PendingVerification>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingVerification {
    pub attestation_hash: [u8; 32],
    pub attestation: Attestation,
    pub intent: Intent,
    pub submitted_at: chrono::DateTime<chrono::Utc>,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    pub intent_hash: [u8; 32],
    pub attestation: SerializableAttestation,
    pub tee_signature: Vec<u8>,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableAttestation {
    pub intent_hash: String,
    pub winner_solver: String,
    pub fill_route: String,
    pub output_amount: String,
    pub block_number: u64,
    pub prev_attest_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResponse {
    pub success: bool,
    pub attestation_hash: [u8; 32],
    pub block_number: u64,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
}

impl VerifierInterface {
    pub fn new(
        verifier_address: Address,
        settlement_address: Address,
        rpc_endpoint: String,
    ) -> Self {
        Self {
            verifier_address,
            settlement_address,
            rpc_endpoint,
            http_client: HttpClient::new(),
            pending_verifications: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Convert TEE attestation to format expected by SolvexVerifier
    pub fn prepare_verification_request(
        &self,
        intent: &Intent,
        attestation: &Attestation,
    ) -> Result<VerificationRequest> {
        let intent_hash = intent.hash();
        
        let serializable_attest = SerializableAttestation {
            intent_hash: hex::encode(attestation.intent_hash),
            winner_solver: attestation.winner_solver.clone(),
            fill_route: attestation.fill_route.to_string(),
            output_amount: attestation.output_amount.to_string(),
            block_number: attestation.block_number,
            prev_attest_hash: hex::encode(attestation.prev_attest_hash),
        };

        Ok(VerificationRequest {
            intent_hash,
            attestation: serializable_attest,
            tee_signature: attestation.signature.clone(),
            block_number: attestation.block_number,
        })
    }

    /// Send attestation to SolvexVerifier for onchain verification.
    /// `attestation_data` = `attestation.to_abi_bytes()` (192 bytes, ABI-encoded Attestation struct)
    /// `tee_sig`          = compact 65-byte `r || s || v` signature
    pub async fn submit_attestation_for_verification(
        &self,
        intent: &Intent,
        attestation: &Attestation,
    ) -> Result<VerificationResponse> {
        let attestation_hash = attestation.hash()?;

        // Use the canonical ABI encoding from Attestation::to_abi_bytes()
        // This is the same bytes the Stylus contract will ABI-decode
        let attestation_bytes = attestation.to_abi_bytes();
        let tee_sig = attestation.signature.clone();

        // Build calldata for SolvexVerifier.verify(intent_hash, attestation_data, tee_sig)
        let calldata = self.build_verify_calldata(&attestation.intent_hash, &attestation_bytes, &tee_sig)?;

        // Send to Arbitrum via JSON-RPC
        let tx_result = self
            .call_p2_verify(intent.hash(), &attestation_bytes, &tee_sig)
            .await;

        // Record pending verification
        let pending = PendingVerification {
            attestation_hash,
            attestation: attestation.clone(),
            intent: intent.clone(),
            submitted_at: chrono::Utc::now(),
            verified_at: None,
        };
        self.pending_verifications.write().await.push(pending);

        match tx_result {
            Ok(tx_hash) => Ok(VerificationResponse {
                success: true,
                attestation_hash,
                block_number: attestation.block_number,
                tx_hash: Some(tx_hash),
                error: None,
            }),
            Err(e) => Ok(VerificationResponse {
                success: false,
                attestation_hash,
                block_number: attestation.block_number,
                tx_hash: None,
                error: Some(e.to_string()),
            }),
        }
    }

    /// Call P2's SolvexVerifier.verify() via Arbitrum RPC
    async fn call_p2_verify(
        &self,
        intent_hash: [u8; 32],
        attestation_bytes: &[u8],
        tee_signature: &[u8],
    ) -> Result<String> {
        // Build calldata for SolvexVerifier.verify(bytes32, bytes, bytes)
        let calldata = self.build_verify_calldata(&intent_hash, attestation_bytes, tee_signature)?;

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [format!("0x{}", hex::encode(&calldata))],
            "id": 1,
        });

        let response = self
            .http_client
            .post(&self.rpc_endpoint)
            .json(&body)
            .send()
            .await
            .map_err(|e| TeeError::InternalError(format!("RPC call failed: {}", e)))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| TeeError::InternalError(format!("Failed to parse RPC response: {}", e)))?;

        if let Some(result) = json.get("result") {
            Ok(result.as_str().unwrap_or("0x").to_string())
        } else if let Some(error) = json.get("error") {
            Err(TeeError::InternalError(format!(
                "RPC error: {}",
                error.get("message").unwrap_or(&serde_json::json!("unknown"))
            )))
        } else {
            Err(TeeError::InternalError("Invalid RPC response".to_string()))
        }
    }


    /// Build calldata for `SolvexVerifier.verify(bytes32 intent_hash, bytes attestation_data, bytes tee_sig)`
    ///
    /// ABI encoding layout (after 4-byte selector):
    ///   offset 0x00: intent_hash   (bytes32, fixed)
    ///   offset 0x20: offset to attestation_data (= 0x60)
    ///   offset 0x40: offset to tee_sig
    ///   offset 0x60: attestation_data.length
    ///   offset 0x80: attestation_data bytes (padded to 32-byte boundary)
    ///   ...       : tee_sig.length
    ///   ...       : tee_sig bytes (padded)
    pub fn build_verify_calldata(
        &self,
        intent_hash: &[u8; 32],
        attestation_bytes: &[u8],
        tee_sig: &[u8],
    ) -> Result<Vec<u8>> {
        // keccak256("verify(bytes32,bytes,bytes)")[0:4] = 0xfc735e99
        let selector: [u8; 4] = [0xfc, 0x73, 0x5e, 0x99];

        let attest_padded_len = ((attestation_bytes.len() + 31) / 32) * 32;
        let sig_padded_len    = ((tee_sig.len() + 31) / 32) * 32;

        // Offsets are relative to the start of the ABI payload (after selector)
        // slot 0: intent_hash   (bytes32, 32 bytes, no offset needed)
        // slot 1: offset of attestation_data = 3 × 32 = 0x60
        // slot 2: offset of tee_sig          = 0x60 + 32 + attest_padded_len
        let attest_offset: u64 = 0x60;
        let sig_offset: u64    = 0x60 + 32 + attest_padded_len as u64;

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&selector);
        out.extend_from_slice(intent_hash);                             // slot 0
        out.extend_from_slice(&pad_u64_to_32(attest_offset));          // slot 1
        out.extend_from_slice(&pad_u64_to_32(sig_offset));             // slot 2
        out.extend_from_slice(&pad_u64_to_32(attestation_bytes.len() as u64)); // length
        out.extend_from_slice(attestation_bytes);                       // data
        out.extend_from_slice(&vec![0u8; attest_padded_len - attestation_bytes.len()]); // pad
        out.extend_from_slice(&pad_u64_to_32(tee_sig.len() as u64));   // length
        out.extend_from_slice(tee_sig);                                 // data
        out.extend_from_slice(&vec![0u8; sig_padded_len - tee_sig.len()]); // pad

        Ok(out)
    }

    /// Confirm verification succeeded onchain
    pub async fn confirm_verification(&self, attestation_hash: &[u8; 32]) -> Result<()> {
        let mut pending = self.pending_verifications.write().await;
        
        if let Some(pos) = pending.iter().position(|p| p.attestation_hash == *attestation_hash) {
            pending[pos].verified_at = Some(chrono::Utc::now());
            Ok(())
        } else {
            Err(TeeError::InternalError(
                "Attestation not found in pending verifications".to_string(),
            ))
        }
    }

    /// Get pending verifications that haven't been confirmed yet
    pub async fn get_pending_verifications(&self) -> Result<Vec<PendingVerification>> {
        Ok(self
            .pending_verifications
            .read()
            .await
            .iter()
            .filter(|p| p.verified_at.is_none())
            .cloned()
            .collect())
    }

    /// Get verification status
    pub async fn get_verification_status(
        &self,
        attestation_hash: &[u8; 32],
    ) -> Result<Option<PendingVerification>> {
        Ok(self
            .pending_verifications
            .read()
            .await
            .iter()
            .find(|p| p.attestation_hash == *attestation_hash)
            .cloned())
    }

    /// Get the verifier contract address
    pub fn get_verifier_address(&self) -> Address {
        self.verifier_address
    }

    /// Get the settlement contract address
    pub fn get_settlement_address(&self) -> Address {
        self.settlement_address
    }

    /// Build the settlement call after verification succeeds
    pub fn build_settlement_calldata(
        &self,
        attestation: &Attestation,
    ) -> Result<Vec<u8>> {
        // Build calldata for SolvexSettlement to release funds
        let mut calldata = Vec::new();
        
        // Function selector for release_funds()
        calldata.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // Placeholder
        
        // Encode attestation details
        calldata.extend_from_slice(&attestation.intent_hash);
        calldata.extend_from_slice(attestation.winner_solver.as_bytes());

        Ok(calldata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::AttestationSigner;
    use crate::types::QuoteData;
    use chrono::Utc;

    #[tokio::test]
    async fn test_verifier_interface_creation() {
        let interface = VerifierInterface::new(
            Address::ZERO,
            Address::ZERO,
            "http://localhost:8545".to_string(),
        );

        assert_eq!(interface.get_verifier_address(), Address::ZERO);
    }

    #[tokio::test]
    async fn test_prepare_verification_request() {
        let interface = VerifierInterface::new(
            Address::ZERO,
            Address::ZERO,
            "http://localhost:8545".to_string(),
        );

        let intent = Intent {
            user: Address::ZERO,
            token_in: Address::ZERO,
            token_out: Address::ZERO,
            amount_in: Default::default(),
            min_amount_out: Default::default(),
            deadline: 0,
            nonce: 1,
        };

        let signer = AttestationSigner::new().unwrap();
        let quote = QuoteData {
            output_amount: Default::default(),
            fill_route: Address::ZERO,
            gas_estimate: Default::default(),
            timestamp: Utc::now(),
            solver_id: "test".to_string(),
        };

        let attestation =
            signer.create_attestation(&intent, &quote, 1, [0u8; 32]).unwrap();
        let req = interface.prepare_verification_request(&intent, &attestation);

        assert!(req.is_ok());
    }

    #[tokio::test]
    async fn test_submit_attestation() {
        let interface = VerifierInterface::new(
            Address::ZERO,
            Address::ZERO,
            "http://localhost:8545".to_string(),
        );

        let intent = Intent {
            user: Address::ZERO,
            token_in: Address::ZERO,
            token_out: Address::ZERO,
            amount_in: Default::default(),
            min_amount_out: Default::default(),
            deadline: 0,
            nonce: 1,
        };

        let signer = AttestationSigner::new().unwrap();
        let quote = QuoteData {
            output_amount: Default::default(),
            fill_route: Address::ZERO,
            gas_estimate: Default::default(),
            timestamp: Utc::now(),
            solver_id: "test".to_string(),
        };

        let attestation = signer.create_attestation(&intent, &quote, 1, [0u8; 32]).unwrap();
        let response = interface.submit_attestation_for_verification(&intent, &attestation).await;

        assert!(response.is_ok());
        // Note: success is false because there's no real RPC endpoint in tests
        // The important thing is that no panic occurred and the response is well-formed
        let resp = response.unwrap();
        assert!(!resp.attestation_hash.iter().all(|&b| b == 0), "attestation hash must be non-zero");
    }

    #[test]
    fn test_calldata_correct_length() {
        let iface = VerifierInterface::new(
            Address::ZERO,
            Address::ZERO,
            "http://localhost:8545".to_string(),
        );
        let intent_hash = [1u8; 32];
        let attest_bytes = vec![0u8; 192]; // 6 × 32
        let tee_sig = vec![0u8; 65];       // compact sig

        let calldata = iface
            .build_verify_calldata(&intent_hash, &attest_bytes, &tee_sig)
            .unwrap();

        // 4 (selector) + 32 (intent_hash) + 32 (attest offset) + 32 (sig offset)
        // + 32 (attest len) + 192 (attest data, already 32-aligned)
        // + 32 (sig len) + 96 (65 bytes padded to 96)
        assert_eq!(calldata.len(), 4 + 32 + 32 + 32 + 32 + 192 + 32 + 96);

        // Check selector
        assert_eq!(&calldata[0..4], &[0xfc, 0x73, 0x5e, 0x99]);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Right-align a u64 value in a 32-byte (256-bit) slot, big-endian.
fn pad_u64_to_32(v: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&v.to_be_bytes());
    buf
}
