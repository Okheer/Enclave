use thiserror::Error;

pub type Result<T> = std::result::Result<T, TeeError>;

#[derive(Error, Debug)]
pub enum TeeError {
    #[error("Invalid quote: {0}")]
    InvalidQuote(String),

    #[error("No quotes submitted for competition")]
    NoQuotesSubmitted,

    #[error("Solver not registered: {0}")]
    SolverNotRegistered(String),

    #[error("ECDSA signing failed: {0}")]
    SigningError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Merkle chain verification failed: {0}")]
    MerkleError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Intent validation failed: {0}")]
    InvalidIntent(String),

    #[error("Quote submission closed")]
    AuctionClosed,

    #[error("Deadline passed")]
    DeadlineExceeded,

    #[error("Insufficient output: expected {expected}, got {actual}")]
    InsufficientOutput { expected: u128, actual: u128 },

    #[error("Internal TEE error: {0}")]
    InternalError(String),

    #[error("Communication error: {0}")]
    CommunicationError(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<serde_json::Error> for TeeError {
    fn from(err: serde_json::Error) -> Self {
        TeeError::SerializationError(err.to_string())
    }
}

impl From<anyhow::Error> for TeeError {
    fn from(err: anyhow::Error) -> Self {
        TeeError::InternalError(err.to_string())
    }
}
