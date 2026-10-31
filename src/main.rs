use clap::Parser;
use rustdrop::Peer;
use rustdrop::cli::{Cli, Commands};
use rustdrop::config::Settings;
use rustdrop::discovery::DiscoveryService;
use rustdrop::error::Result;
use rustdrop::security::{Identity, short_fingerprint};
use rustdrop::transfer::{Receiver, send_file, send_text};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{Level, error, info};
use tracing_subscriber::FmtSubscriber;

/// How long to listen for announcements before acting on the peer list
const DISCOVERY_WAIT: Duration = Duration::from_secs(3);

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider (ring)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
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

    info!(
        "Device: {} (fingerprint: {})",
        settings.device_name,
        identity.short_fingerprint()
    );

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
    if !file_path.exists() {
        return Err(rustdrop::RustDropError::Transfer(format!(
            "File not found: {:?}",
            file_path
        )));
    }

    match find_peer(settings, &identity.fingerprint, target).await? {
        Some(peer) => send_file(&peer, file_path, &settings.device_name).await,
        None => Ok(()),
    }
}

async fn cmd_text(
    settings: &Settings,
    identity: &Identity,
    message: &str,
    target: Option<String>,
) -> Result<()> {
    match find_peer(settings, &identity.fingerprint, target).await? {
        Some(peer) => send_text(&peer, message, &settings.device_name).await,
        None => Ok(()),
    }
}

/// Run discovery for a few seconds, then resolve the peer to send to.
///
/// `target` matches either a 1-based index from the listing or a case-insensitive
/// substring of a device name; without one, the user picks interactively.
/// Returns `Ok(None)` when no peer was found or selected, having already told the
/// user why.
async fn find_peer(
    settings: &Settings,
    fingerprint: &str,
    target: Option<String>,
) -> Result<Option<Peer>> {
    info!("Discovering peers...");

    let discovery = DiscoveryService::new(settings, fingerprint.to_string());
    let peers_handle = discovery.peers();

    let discovery_handle = tokio::spawn(async move {
        let _ = discovery.run().await;
    });

    sleep(DISCOVERY_WAIT).await;

    let peer_list: Vec<Peer> = peers_handle.read().await.values().cloned().collect();
    discovery_handle.abort();

    if peer_list.is_empty() {
        println!("No peers found. Make sure another device is running 'rustdrop listen'");
        return Ok(None);
    }

    let selected = match target {
        Some(target) => match_peer(&peer_list, &target),
        None => prompt_for_peer(&peer_list),
    };

    if selected.is_none() {
        println!("No matching peer selected");
    }

    Ok(selected)
}

/// Match a peer by 1-based index or by a substring of its device name
fn match_peer(peers: &[Peer], target: &str) -> Option<Peer> {
    if let Ok(index) = target.parse::<usize>() {
        return peers.get(index.saturating_sub(1)).cloned();
    }

    let target = target.to_lowercase();
    peers
        .iter()
        .find(|p| p.device_name.to_lowercase().contains(&target))
        .cloned()
}

/// Show the discovered peers and let the user pick one
fn prompt_for_peer(peers: &[Peer]) -> Option<Peer> {
    println!("\nAvailable peers:");
    for (i, peer) in peers.iter().enumerate() {
        println!("  [{}] {} ({})", i + 1, peer.device_name, peer.ip_addr);
    }

    print!("\nSelect peer (1-{}): ", peers.len());
    io::stdout().flush().ok()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).ok()?;

    let index = input.trim().parse::<usize>().ok()?;
    peers.get(index.saturating_sub(1)).cloned()
}

async fn cmd_receive(settings: &Settings, identity: Identity, auto_accept: bool) -> Result<()> {
    info!("Starting receive mode...");
    info!("Download directory: {:?}", settings.download_dir);

    let shutdown_rx = shutdown_on_ctrl_c();

    let receiver = Receiver::new(settings.clone(), identity, auto_accept);
    receiver.run(shutdown_rx).await?;

    Ok(())
}

async fn cmd_listen(settings: &Settings, identity: Identity, auto_accept: bool) -> Result<()> {
    info!("Starting in listen mode (discovery + receive)...");
    info!("Download directory: {:?}", settings.download_dir);

    let shutdown_rx = shutdown_on_ctrl_c();

    let discovery = DiscoveryService::new(settings, identity.fingerprint.clone());
    let receiver = Receiver::new(settings.clone(), identity, auto_accept);

    // Whichever side stops first ends the command
    tokio::select! {
        result = discovery.run() => {
            if let Err(e) = result {
                error!("Discovery error: {}", e);
            }
        }
        result = receiver.run(shutdown_rx) => {
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

    let discovery_handle = tokio::spawn(async move {
        let _ = discovery.run().await;
    });

    if watch_mode {
        println!("Press Ctrl+C to stop\n");

        let mut shutdown_rx = shutdown_on_ctrl_c();

        loop {
            tokio::select! {
                _ = sleep(Duration::from_secs(2)) => {
                    let peers: Vec<_> = peers_handle.read().await.values().cloned().collect();
                    print!("\x1B[2J\x1B[1;1H");
                    print_peers(&peers);
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    } else {
        sleep(Duration::from_secs(timeout_secs)).await;
        let peers: Vec<_> = peers_handle.read().await.values().cloned().collect();
        print_peers(&peers);
    }

    discovery_handle.abort();
    Ok(())
}

fn print_peers(peers: &[Peer]) {
    if peers.is_empty() {
        println!("No peers discovered yet...");
        return;
    }

    println!("Discovered peers:");
    println!("{:-<50}", "");
    for (i, peer) in peers.iter().enumerate() {
        println!(
            "  [{}] {} \n      IP: {} | Port: {} | Fingerprint: {}",
            i + 1,
            peer.device_name,
            peer.ip_addr,
            peer.transfer_port,
            short_fingerprint(&peer.fingerprint)
        );
    }
    println!("{:-<50}", "");
    println!("Total: {} peer(s)", peers.len());
}

fn cmd_identity(settings: &Settings, regenerate: bool) -> Result<()> {
    if regenerate {
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

/// Flip a watch channel to `true` when the user presses Ctrl+C
fn shutdown_on_ctrl_c() -> watch::Receiver<bool> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down...");
        let _ = shutdown_tx.send(true);
    });

    shutdown_rx
}
