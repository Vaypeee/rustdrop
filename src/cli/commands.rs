use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// RustDrop - Local network file transfer CLI
#[derive(Parser, Debug)]
#[command(name = "rustdrop")]
#[command(author = "Amine")]
#[command(version = "0.1.0")]
#[command(about = "AirDrop alternative - Transfer files over local network", long_about = None)]
pub struct Cli {
    /// Device name to announce on the network
    #[arg(short = 'n', long, global = true)]
    pub device_name: Option<String>,

    /// Port for file transfers
    #[arg(short = 'p', long, default_value = "9000", global = true)]
    pub port: u16,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Send a file to a peer
    Send {
        /// Path to the file to send
        #[arg(required = true)]
        file: PathBuf,

        /// Target peer name or index (optional, will prompt if not provided)
        #[arg(short, long)]
        to: Option<String>,
    },

    /// Send text/message to a peer
    Text {
        /// The text message to send
        #[arg(required = true)]
        message: String,

        /// Target peer name or index (optional, will prompt if not provided)
        #[arg(short, long)]
        to: Option<String>,
    },

    /// Start receiving mode (listen for incoming transfers)
    Receive {
        /// Download directory for received files
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Automatically accept all incoming transfers
        #[arg(short, long)]
        accept_all: bool,
    },

    /// Listen for peers and accept transfers (combined mode)
    Listen {
        /// Download directory for received files
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Automatically accept all incoming transfers
        #[arg(short, long)]
        accept_all: bool,
    },

    /// List discovered peers on the network
    #[command(name = "list-peers")]
    ListPeers {
        /// Keep scanning and update the list
        #[arg(short, long)]
        watch: bool,

        /// Scan duration in seconds (default: 5)
        #[arg(short, long, default_value = "5")]
        timeout: u64,
    },

    /// Generate or show identity certificate info
    Identity {
        /// Regenerate the certificate
        #[arg(long)]
        regenerate: bool,
    },
}
