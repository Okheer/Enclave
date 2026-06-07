use crate::error::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::info;
use hex;

/// HTTP API for TEE Solver Engine
/// Solvers submit quotes here during the sealed auction

#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<crate::TeeSolverEngine>,
    pub attestation_token: Arc<tokio::sync::RwLock<crate::gcp_attestation::AttestationToken>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuoteSubmissionRequest {
    pub solver_id: String,
    pub output_amount: String,
    pub fill_route: String,
    pub gas_estimate: String,
    pub intent_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuoteSubmissionResponse {
    pub success: bool,
    pub message: String,
    pub quote_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    pub status: String,
    pub version: String,
    pub public_key: String,
    pub tee_ethereum_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuctionStatusResponse {
    pub is_active: bool,
    pub total_quotes: u32,
    pub quotes_per_solver: Vec<(String, u32)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
}

/// Create the API router
pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/pubkey", get(get_public_key))
        .route("/attestation", get(get_attestation))  // GCP hardware attestation info
        .route("/start", post(start_auction))        // open a sealed auction
        .route("/quote", post(submit_quote))
        .route("/status", get(auction_status))
        .route("/finalize", post(finalize_and_verify))
        .route("/verification-status/:hash", get(verification_status))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

/// Health check endpoint — verify TEE is operational
async fn health_check(State(state): State<ApiState>) -> impl IntoResponse {
    match state.engine.get_public_key() {
        Ok(pubkey) => {
            let eth_addr = state
                .engine
                .get_ethereum_address()
                .map(|a| format!("{:?}", a))
                .unwrap_or_else(|_| "unknown".into());
            let response = HealthCheckResponse {
                status: "ok".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                public_key: hex::encode(&pubkey),
                tee_ethereum_address: eth_addr,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let error = ErrorResponse {
                error: format!("Health check failed: {}", e),
                code: 500,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// Get TEE's public key and Ethereum address for onchain registration
async fn get_public_key(State(state): State<ApiState>) -> impl IntoResponse {
    match state.engine.get_public_key() {
        Ok(pubkey) => {
            let eth_addr = state
                .engine
                .get_ethereum_address()
                .map(|a| format!("{:?}", a))
                .unwrap_or_else(|_| "unknown".into());
            #[derive(Serialize)]
            struct Response {
                public_key_compressed: String,
                /// Register THIS address in SolverRegistry.sol and SolvexVerifier
                tee_ethereum_address: String,
            }
            (
                StatusCode::OK,
                Json(Response {
                    public_key_compressed: hex::encode(&pubkey),
                    tee_ethereum_address: eth_addr,
                }),
            )
                .into_response()
        }
        Err(e) => {
            let error = ErrorResponse {
                error: format!("Failed to get public key: {}", e),
                code: 500,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// GET /attestation — returns the full GCP attestation token
async fn get_attestation(State(state): State<ApiState>) -> impl IntoResponse {
    let token = state.attestation_token.read().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "mode": if token.is_simulation { "simulation" } else { "hardware" },
            "image_digest": token.image_digest,
            "tee_pubkey": token.tee_pubkey,
            "jwt_preview": token.jwt_preview(),
            "jwt": token.jwt,
            "gcp_verification_note": "In production: verify JWT at https://www.googleapis.com/oauth2/v3/certs",
            "synddb_reference": "Same pattern as github.com/SyndicateProtocol/synddb/crates/gcp-attestation"
        }))
    )
}

/// Submit a quote during sealed auction
async fn submit_quote(
    State(state): State<ApiState>,
    Json(payload): Json<QuoteSubmissionRequest>,
) -> impl IntoResponse {
    info!(
        "Quote submission from solver: {} for amount: {}",
        payload.solver_id, payload.output_amount
    );

    // Parse the quote data
    let quote = match parse_quote_request(&payload) {
        Ok(q) => q,
        Err(e) => {
            let error = ErrorResponse {
                error: format!("Invalid quote format: {}", e),
                code: 400,
            };
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }
    };

    // Submit to engine
    match state.engine.submit_quote(payload.solver_id.clone(), quote) {
        Ok(_) => {
            let response = QuoteSubmissionResponse {
                success: true,
                message: "Quote received and sealed".to_string(),
                quote_id: Some(format!("q_{}", chrono::Utc::now().timestamp_millis())),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let error = ErrorResponse {
                error: format!("Quote submission failed: {}", e),
                code: 400,
            };
            (StatusCode::BAD_REQUEST, Json(error)).into_response()
        }
    }
}

/// Get current auction status
async fn auction_status(State(_state): State<ApiState>) -> impl IntoResponse {
    #[derive(Serialize)]
    struct Status {
        is_active: bool,
        message: String,
    }

    let status = Status {
        is_active: true,
        message: "Auction ongoing - submit quotes now".to_string(),
    };

    (StatusCode::OK, Json(status)).into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /start — open a new sealed auction for a given intent hash
// Called by P1 (IntentPool) when a new intent arrives.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct StartAuctionRequest {
    /// 0x-prefixed 32-byte intent hash from IntentPool.sol
    pub intent_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StartAuctionResponse {
    pub success: bool,
    pub intent_hash: String,
    pub message: String,
    pub tee_public_key: String,
}

/// Open a new sealed auction for the given intent hash.
/// P1 calls this immediately after recording the intent in IntentPool.
async fn start_auction(
    State(state): State<ApiState>,
    Json(payload): Json<StartAuctionRequest>,
) -> impl IntoResponse {
    info!("Starting new sealed auction for intent: {}", payload.intent_hash);

    // Parse intent hash from hex string
    let intent_hash_bytes = match hex::decode(payload.intent_hash.trim_start_matches("0x")) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            let error = ErrorResponse {
                error: "Invalid intent_hash: must be a 0x-prefixed 32-byte hex string".to_string(),
                code: 400,
            };
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }
    };

    // Start the sealed competition
    match state.engine.start_competition(intent_hash_bytes) {
        Ok(_) => {
            let pubkey = state
                .engine
                .get_public_key()
                .map(|k| hex::encode(&k))
                .unwrap_or_default();

            let response = StartAuctionResponse {
                success: true,
                intent_hash: payload.intent_hash,
                message: "Sealed auction opened — solvers may now POST to /quote".to_string(),
                tee_public_key: pubkey,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let error = ErrorResponse {
                error: format!("Failed to start auction: {}", e),
                code: 409,
            };
            (StatusCode::CONFLICT, Json(error)).into_response()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinalizeRequest {
    pub intent_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinalizeResponse {
    pub success: bool,
    pub winner_solver: String,
    pub output_amount: String,
    pub attestation_hash: String,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
}

/// Finalize competition and submit attestation to P2 for verification
async fn finalize_and_verify(
    State(state): State<ApiState>,
    Json(payload): Json<FinalizeRequest>,
) -> impl IntoResponse {
    info!("Finalizing competition and submitting to P2");

    // Parse intent hash
    let intent_hash_bytes = match hex::decode(&payload.intent_hash.trim_start_matches("0x")) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            let error = ErrorResponse {
                error: "Invalid intent_hash format".to_string(),
                code: 400,
            };
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }
    };

    // Finalize the competition on P3
    match state.engine.finalize_competition_with_intent_hash(
        &intent_hash_bytes,
        payload.block_number,
    ) {
        Ok(attestation) => {
            let response = FinalizeResponse {
                success: true,
                winner_solver: attestation.winner_solver.clone(),
                output_amount: attestation.output_amount.to_string(),
                attestation_hash: hex::encode(attestation.hash().unwrap_or_default()),
                tx_hash: Some(format!("0x{}", hex::encode(&intent_hash_bytes))),
                error: None,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            let response = FinalizeResponse {
                success: false,
                winner_solver: String::new(),
                output_amount: String::new(),
                attestation_hash: String::new(),
                tx_hash: None,
                error: Some(e.to_string()),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response)).into_response()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationStatusResponse {
    pub attestation_hash: String,
    pub verified: bool,
    pub verified_at: Option<String>,
    pub submitted_at: String,
}

/// Check verification status of an attestation
async fn verification_status(
    State(_state): State<ApiState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> impl IntoResponse {
    let hash_bytes = match hex::decode(hash.trim_start_matches("0x")) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            let error = ErrorResponse {
                error: "Invalid attestation hash format".to_string(),
                code: 400,
            };
            return (StatusCode::BAD_REQUEST, Json(error)).into_response();
        }
    };

    let response = VerificationStatusResponse {
        attestation_hash: hex::encode(hash_bytes),
        verified: false,
        verified_at: None,
        submitted_at: chrono::Utc::now().to_rfc3339(),
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// Parse a quote submission request into QuoteData
fn parse_quote_request(req: &QuoteSubmissionRequest) -> Result<crate::types::QuoteData> {
    use alloy_primitives::{Address, U256};
    use std::str::FromStr;

    let output_amount = U256::from_str(&req.output_amount)
        .map_err(|e| crate::error::TeeError::InvalidQuote(format!("Invalid output_amount: {}", e)))?;

    let hex = req.fill_route.trim_start_matches("0x");
let bytes = hex::decode(hex)
    .map_err(|e| crate::error::TeeError::InvalidQuote(format!("Invalid fill_route: {}", e)))?;
let fill_route = Address::from_slice(&bytes);

    let gas_estimate = U256::from_str(&req.gas_estimate)
        .map_err(|e| crate::error::TeeError::InvalidQuote(format!("Invalid gas_estimate: {}", e)))?;

    Ok(crate::types::QuoteData {
        output_amount,
        fill_route,
        gas_estimate,
        timestamp: chrono::Utc::now(),
        solver_id: req.solver_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_quote() {
        let req = QuoteSubmissionRequest {
            solver_id: "solver1".to_string(),
            output_amount: "1000".to_string(),
            fill_route: "0x0000000000000000000000000000000000000000".to_string(),
            gas_estimate: "100000".to_string(),
            intent_hash: "0x".to_string() + &"00".repeat(32),
        };

        let result = parse_quote_request(&req);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_quote_amount() {
        let req = QuoteSubmissionRequest {
            solver_id: "solver1".to_string(),
            output_amount: "invalid".to_string(),
            fill_route: "0x0000000000000000000000000000000000000000".to_string(),
            gas_estimate: "100000".to_string(),
            intent_hash: "0x".to_string() + &"00".repeat(32),
        };

        let result = parse_quote_request(&req);
        assert!(result.is_err());
    }
}
