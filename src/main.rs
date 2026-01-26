use clap::Parser;
use rustdrop::cli::{Cli, Commands};
use rustls;
use rustdrop::config::Settings;
use rustdrop::discovery::DiscoveryService;
use rustdrop::error::Result;
use rustdrop::security::Identity;
use rustdrop::transfer::{send_file, Receiver};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider (ring)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    // Load settings
    let mut settings = Settings::new();
    if let Some(name) = cli.device_name {
        settings = settings.with_device_name(name);
    }
    settings = settings.with_transfer_port(cli.port);

    // Load or generate identity
    let identity = Identity::load_or_generate(
        &settings.cert_path(),
        &settings.key_path(),
        &settings.device_name,
    )?;

    info!("Device: {} (fingerprint: {})", settings.device_name, identity.fingerprint);

    match cli.command {
        Commands::Send { file, to } => {
            cmd_send(&settings, &identity, &file, to).await?;
        }
        Commands::Text { message, to } => {
            cmd_text(&settings, &identity, &message, to).await?;
        }
        Commands::Receive { output, accept_all } => {
            if let Some(dir) = output {
                settings = settings.with_download_dir(dir);
            }
            cmd_receive(&settings, identity, accept_all).await?;
        }
        Commands::Listen { output, accept_all } => {
            if let Some(dir) = output {
                settings = settings.with_download_dir(dir);
            }
            cmd_listen(&settings, identity, accept_all).await?;
        }
        Commands::ListPeers { watch, timeout } => {
            cmd_list_peers(&settings, &identity.fingerprint, watch, timeout).await?;
        }
        Commands::Identity { regenerate } => {
            cmd_identity(&settings, regenerate)?;
        }
    }

    Ok(())
}

async fn cmd_send(
    settings: &Settings,
    identity: &Identity,
    file_path: &PathBuf,
    target: Option<String>,
) -> Result<()> {
    // Verify file exists
    if !file_path.exists() {
        return Err(rustdrop::RustDropError::Transfer(format!(
            "File not found: {:?}",
            file_path
        )));
    }

    info!("Discovering peers...");

    // Start discovery
    let discovery = DiscoveryService::new(settings, identity.fingerprint.clone());
    let peers_handle = discovery.peers();

    // Run discovery in background
    let discovery_handle = tokio::spawn({
        let discovery = discovery;
        async move {
            let _ = discovery.run().await;
        }
    });

    // Wait for peers
    sleep(Duration::from_secs(3)).await;

    // Get discovered peers
    let peers = peers_handle.read().await;
    let peer_list: Vec<_> = peers.values().cloned().collect();
    drop(peers);

    if peer_list.is_empty() {
        println!("No peers found. Make sure another device is running 'rustdrop listen'");
        discovery_handle.abort();
        return Ok(());
    }

    // Select peer
    let selected_peer = if let Some(ref target_name) = target {
        // Find by name or index
        if let Ok(idx) = target_name.parse::<usize>() {
            peer_list.get(idx.saturating_sub(1)).cloned()
        } else {
            peer_list
                .iter()
                .find(|p| p.device_name.to_lowercase().contains(&target_name.to_lowercase()))
                .cloned()
        }
    } else {
        // Interactive selection
        println!("\nAvailable peers:");
        for (i, peer) in peer_list.iter().enumerate() {
            println!("  [{}] {} ({})", i + 1, peer.device_name, peer.ip_addr);
        }

        print!("\nSelect peer (1-{}): ", peer_list.len());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        if let Ok(idx) = input.trim().parse::<usize>() {
            peer_list.get(idx.saturating_sub(1)).cloned()
        } else {
            None
        }
    };

    let peer = match selected_peer {
        Some(p) => p,
        None => {
            println!("Invalid peer selection");
            discovery_handle.abort();
            return Ok(());
        }
    };

    // Send file
    send_file(&peer, file_path, &settings.device_name).await?;

    discovery_handle.abort();
    Ok(())
}

async fn cmd_text(
    settings: &Settings,
    identity: &Identity,
    message: &str,
    target: Option<String>,
) -> Result<()> {
    info!("Discovering peers...");

    // Start discovery
    let discovery = DiscoveryService::new(settings, identity.fingerprint.clone());
    let peers_handle = discovery.peers();

    // Run discovery in background
    let discovery_handle = tokio::spawn({
        let discovery = discovery;
        async move {
            let _ = discovery.run().await;
        }
    });

    // Wait for peers
    sleep(Duration::from_secs(3)).await;

    // Get discovered peers
    let peers = peers_handle.read().await;
    let peer_list: Vec<_> = peers.values().cloned().collect();
    drop(peers);

    if peer_list.is_empty() {
        println!("No peers found. Make sure another device is running 'rustdrop listen'");
        discovery_handle.abort();
        return Ok(());
    }

    // Select peer
    let selected_peer = if let Some(ref target_name) = target {
        // Find by name or index
        if let Ok(idx) = target_name.parse::<usize>() {
            peer_list.get(idx.saturating_sub(1)).cloned()
        } else {
            peer_list
                .iter()
                .find(|p| p.device_name.to_lowercase().contains(&target_name.to_lowercase()))
                .cloned()
        }
    } else {
        // Interactive selection
        println!("\nAvailable peers:");
        for (i, peer) in peer_list.iter().enumerate() {
            println!("  [{}] {} ({})", i + 1, peer.device_name, peer.ip_addr);
        }

        print!("\nSelect peer (1-{}): ", peer_list.len());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        if let Ok(idx) = input.trim().parse::<usize>() {
            peer_list.get(idx.saturating_sub(1)).cloned()
        } else {
            None
        }
    };

    let peer = match selected_peer {
        Some(p) => p,
        None => {
            println!("Invalid peer selection");
            discovery_handle.abort();
            return Ok(());
        }
    };

    // Create temporary file with message
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("rustdrop_message.txt");
    tokio::fs::write(&temp_file, message).await?;

    // Send file
    send_file(&peer, &temp_file, &settings.device_name).await?;

    // Cleanup
    let _ = tokio::fs::remove_file(&temp_file).await;

    discovery_handle.abort();
    Ok(())
}

async fn cmd_receive(settings: &Settings, identity: Identity, auto_accept: bool) -> Result<()> {
    info!("Starting receive mode...");
    info!("Download directory: {:?}", settings.download_dir);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Setup Ctrl+C handler
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down...");
        let _ = shutdown_tx_clone.send(true);
    });

    let receiver = Receiver::new(settings.clone(), identity, auto_accept);
    receiver.run(shutdown_rx).await?;

    Ok(())
}

async fn cmd_listen(settings: &Settings, identity: Identity, auto_accept: bool) -> Result<()> {
    info!("Starting in listen mode (discovery + receive)...");
    info!("Download directory: {:?}", settings.download_dir);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Setup Ctrl+C handler
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down...");
        let _ = shutdown_tx_clone.send(true);
    });

    // Start discovery service
    let discovery = DiscoveryService::new(settings, identity.fingerprint.clone());

    // Start receiver
    let receiver = Receiver::new(settings.clone(), identity, auto_accept);

    // Run both concurrently
    let receiver_shutdown = shutdown_rx.clone();

    tokio::select! {
        result = discovery.run() => {
            if let Err(e) = result {
                error!("Discovery error: {}", e);
            }
        }
        result = receiver.run(receiver_shutdown) => {
            if let Err(e) = result {
                error!("Receiver error: {}", e);
            }
        }
    }

    Ok(())
}

async fn cmd_list_peers(
    settings: &Settings,
    fingerprint: &str,
    watch_mode: bool,
    timeout_secs: u64,
) -> Result<()> {
    info!("Scanning for peers...");

    let discovery = DiscoveryService::new(settings, fingerprint.to_string());
    let peers_handle = discovery.peers();

    // Run discovery in background
    let discovery_handle = tokio::spawn({
        let discovery = discovery;
        async move {
            let _ = discovery.run().await;
        }
    });

    if watch_mode {
        // Continuous mode
        println!("Press Ctrl+C to stop\n");

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            let _ = shutdown_tx.send(true);
        });

        loop {
            tokio::select! {
                _ = sleep(Duration::from_secs(2)) => {
                    print_peers(&peers_handle.read().await.values().cloned().collect::<Vec<_>>());
                }
                _ = shutdown_rx.changed() => {
                    break;
                }
            }
        }
    } else {
        // One-shot mode
        sleep(Duration::from_secs(timeout_secs)).await;
        let peers: Vec<_> = peers_handle.read().await.values().cloned().collect();
        print_peers(&peers);
    }

    discovery_handle.abort();
    Ok(())
}

fn print_peers(peers: &[rustdrop::Peer]) {
    // Clear screen for watch mode
    print!("\x1B[2J\x1B[1;1H");

    if peers.is_empty() {
        println!("No peers discovered yet...");
    } else {
        println!("Discovered peers:");
        println!("{:-<50}", "");
        for (i, peer) in peers.iter().enumerate() {
            println!(
                "  [{}] {} \n      IP: {} | Port: {} | Fingerprint: {}",
                i + 1,
                peer.device_name,
                peer.ip_addr,
                peer.transfer_port,
                &peer.fingerprint[..8.min(peer.fingerprint.len())]
            );
        }
        println!("{:-<50}", "");
        println!("Total: {} peer(s)", peers.len());
    }
}

fn cmd_identity(settings: &Settings, regenerate: bool) -> Result<()> {
    if regenerate {
        // Delete existing certs
        let _ = std::fs::remove_file(settings.cert_path());
        let _ = std::fs::remove_file(settings.key_path());
        println!("Regenerating identity...");
    }

    let identity = Identity::load_or_generate(
        &settings.cert_path(),
        &settings.key_path(),
        &settings.device_name,
    )?;

    println!("\nIdentity Information:");
    println!("{:-<40}", "");
    println!("Device Name:  {}", settings.device_name);
    println!("Fingerprint:  {}", identity.fingerprint);
    println!("Certificate:  {:?}", settings.cert_path());
    println!("Private Key:  {:?}", settings.key_path());
    println!("{:-<40}", "");

    Ok(())
}
