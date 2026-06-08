use std::sync::Arc;
use tokio::signal;
use tracing::info;
use tee_solver::{TeeSolverEngine, api::{ApiState, create_router}};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting PRISM TEE Solver Engine");

    // Initialize TEE Solver Engine
    let engine = Arc::new(TeeSolverEngine::new()?);
    let pubkey = engine.get_public_key()?;
    let eth_addr = engine.get_ethereum_address()?;
    
    info!("TEE Solver Engine initialized");
    let tee_pubkey_hex = hex::encode(&pubkey);
    info!("Public Key (compressed): 0x{}", tee_pubkey_hex);
    info!("TEE Ethereum Address:    {:?}", eth_addr);

    // At startup, fetch attestation token and print it
    let attest_token = tee_solver::gcp_attestation::AttestationToken::fetch(&tee_pubkey_hex).await?;

    if attest_token.is_simulation {
        tracing::warn!("ATTESTATION MODE: {}", attest_token.mode_str());
        tracing::warn!("Image digest (simulated PCR0): {}", attest_token.image_digest);
    } else {
        tracing::info!("ATTESTATION MODE: {}", attest_token.mode_str());
        tracing::info!("Image digest (real PCR0): {}", attest_token.image_digest);
        tracing::info!("GCP attestation JWT: {}", attest_token.jwt_preview());
    }
    info!(">>> P1: register this pubkey in SolverRegistry.sol: 0x{}", tee_pubkey_hex);
    info!(">>> P1: bind to image_digest: {}", attest_token.image_digest);

    // Create API server
    let api_state = ApiState {
        engine: engine.clone(),
        attestation_token: Arc::new(tokio::sync::RwLock::new(attest_token)),
    };

    let app = create_router(api_state);

    // Start listener
    let addr = "0.0.0.0:8080";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    info!("TEE Solver Engine listening on http://{}", addr);
    info!("  POST /start   — open a new sealed auction");
    info!("  POST /quote   — solver quote submission");
    info!("  GET  /pubkey  — TEE public key + Ethereum address");
    info!("  POST /finalize — finalize competition, get attestation");
    info!("  GET  /health  — health check");

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("TEE Solver Engine shutdown complete");
    Ok(())
}

/// Listen for shutdown signals
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received CTRL+C, initiating shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating shutdown");
        }
    }
}
