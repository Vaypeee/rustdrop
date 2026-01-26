use crate::config::PEER_TIMEOUT_SECS;
use crate::discovery::peer::{Announcement, Peer};
use crate::error::{Result, RustDropError};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{watch, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};
use uuid::Uuid;

/// Listens for peer announcements and maintains the peer list
pub struct Listener {
    instance_id: Uuid,
    discovery_port: u16,
    peers: Arc<RwLock<HashMap<Uuid, Peer>>>,
}

impl Listener {
    pub fn new(instance_id: Uuid, discovery_port: u16) -> Self {
        Self {
            instance_id,
            discovery_port,
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get a clone of the peers map handle
    pub fn peers(&self) -> Arc<RwLock<HashMap<Uuid, Peer>>> {
        Arc::clone(&self.peers)
    }

    /// Get current list of peers
    pub async fn get_peers(&self) -> Vec<Peer> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Start listening for announcements
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let socket = create_listener_socket(self.discovery_port)?;
        let socket = UdpSocket::from_std(socket)?;

        info!(
            "Listening for announcements on port {}",
            self.discovery_port
        );

        let mut buf = vec![0u8; 4096];
        let mut cleanup_ticker = interval(Duration::from_secs(PEER_TIMEOUT_SECS / 2));

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src_addr)) => {
                            self.handle_packet(&buf[..len], src_addr).await;
                        }
                        Err(e) => {
                            error!("Error receiving packet: {}", e);
                        }
                    }
                }
                _ = cleanup_ticker.tick() => {
                    self.cleanup_expired_peers().await;
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Listener shutting down");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_packet(&self, data: &[u8], src_addr: SocketAddr) {
        // Try to deserialize the announcement
        let announcement: Announcement = match serde_json::from_slice(data) {
            Ok(a) => a,
            Err(e) => {
                debug!("Failed to parse announcement from {}: {}", src_addr, e);
                return;
            }
        };

        // Ignore self-announcements
        if announcement.instance_id == self.instance_id {
            debug!("Ignoring self-announcement");
            return;
        }

        // Extract IP from source address
        let peer_ip = src_addr.ip();

        // Update or add peer
        let mut peers = self.peers.write().await;
        if let Some(existing) = peers.get_mut(&announcement.instance_id) {
            existing.touch();
            debug!("Updated peer '{}' at {}", existing.device_name, peer_ip);
        } else {
            let peer = announcement.to_peer(peer_ip);
            info!("Discovered new peer: '{}' at {}", peer.device_name, peer_ip);
            peers.insert(announcement.instance_id, peer);
        }
    }

    async fn cleanup_expired_peers(&self) {
        let mut peers = self.peers.write().await;
        let before_count = peers.len();

        peers.retain(|_, peer| {
            let expired = peer.is_expired(PEER_TIMEOUT_SECS);
            if expired {
                info!("Peer '{}' timed out", peer.device_name);
            }
            !expired
        });

        let removed = before_count - peers.len();
        if removed > 0 {
            debug!("Removed {} expired peers", removed);
        }
    }
}

/// Create a UDP socket with SO_REUSEADDR/SO_REUSEPORT for the listener
fn create_listener_socket(port: u16) -> Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| RustDropError::Network(format!("Failed to create socket: {}", e)))?;

    socket
        .set_reuse_address(true)
        .map_err(|e| RustDropError::Network(format!("Failed to set SO_REUSEADDR: {}", e)))?;

    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .map_err(|e| RustDropError::Network(format!("Failed to set SO_REUSEPORT: {}", e)))?;

    socket.set_nonblocking(true).map_err(|e| {
        RustDropError::Network(format!("Failed to set non-blocking: {}", e))
    })?;

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    socket
        .bind(&addr.into())
        .map_err(|e| RustDropError::Network(format!("Failed to bind to port {}: {}", port, e)))?;

    Ok(socket.into())
}
