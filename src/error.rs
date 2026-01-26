use std::io;
use thiserror::Error;

/// Custom error types for RustDrop
#[derive(Error, Debug)]
pub enum RustDropError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Transfer error: {0}")]
    Transfer(String),

    #[error("Discovery error: {0}")]
    Discovery(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Transfer rejected by peer")]
    TransferRejected,

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Timeout: {0}")]
    Timeout(String),
}

pub type Result<T> = std::result::Result<T, RustDropError>;
