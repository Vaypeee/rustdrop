use crate::config::{ANNOUNCE_INTERVAL_SECS, Settings};
use crate::discovery::peer::Announcement;
use crate::error::Result;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{Duration, interval};
use tracing::{debug, error, info};
use uuid::Uuid;

/// Broadcasts presence announcements over UDP
pub struct Announcer {
    instance_id: Uuid,
    announcement: Announcement,
    discovery_port: u16,
}

impl Announcer {
    pub fn new(instance_id: Uuid, settings: &Settings, fingerprint: String) -> Self {
        let announcement = Announcement::new(
            instance_id,
            settings.device_name.clone(),
            settings.transfer_port,
            fingerprint,
        );

        Self {
            instance_id,
            announcement,
            discovery_port: settings.discovery_port,
        }
    }

    /// Start broadcasting announcements
    /// Returns when shutdown signal is received
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        // Bind to any available port for sending
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.set_broadcast(true)?;

        let broadcast_addr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, self.discovery_port));

        let message = serde_json::to_vec(&self.announcement)?;

        info!(
            "Starting announcer for '{}' ({})",
            self.announcement.device_name, self.instance_id
        );

        let mut ticker = interval(Duration::from_secs(ANNOUNCE_INTERVAL_SECS));

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match socket.send_to(&message, broadcast_addr).await {
                        Ok(bytes) => {
                            debug!(
                                "Sent announcement ({} bytes) to {}",
                                bytes, broadcast_addr
                            );
                        }
                        Err(e) => {
                            error!("Failed to send announcement: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Announcer shutting down");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Creates a UDP socket suitable for broadcasting
pub async fn create_broadcast_socket() -> Result<UdpSocket> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;
    Ok(socket)
}
