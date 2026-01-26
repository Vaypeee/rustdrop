//! RustDrop - Local network file transfer library
//!
//! A Rust implementation of AirDrop-like file transfers over local network.

pub mod cli;
pub mod config;
pub mod discovery;
pub mod error;
pub mod security;
pub mod transfer;

pub use config::Settings;
pub use discovery::{DiscoveryService, Peer};
pub use error::{Result, RustDropError};
pub use security::Identity;
pub use transfer::{send_file, Receiver};
