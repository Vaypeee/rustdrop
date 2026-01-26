use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Instant;
use uuid::Uuid;

/// Represents a discovered peer on the network
#[derive(Debug, Clone)]
pub struct Peer {
    pub instance_id: Uuid,
    pub device_name: String,
    pub ip_addr: IpAddr,
    pub transfer_port: u16,
    pub fingerprint: String,
    pub last_seen: Instant,
}

impl Peer {
    pub fn new(
        instance_id: Uuid,
        device_name: String,
        ip_addr: IpAddr,
        transfer_port: u16,
        fingerprint: String,
    ) -> Self {
        Self {
            instance_id,
            device_name,
            ip_addr,
            transfer_port,
            fingerprint,
            last_seen: Instant::now(),
        }
    }

    /// Update last seen timestamp
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Check if peer has timed out
    pub fn is_expired(&self, timeout_secs: u64) -> bool {
        self.last_seen.elapsed().as_secs() > timeout_secs
    }

    /// Get the full address for TCP connection
    pub fn transfer_addr(&self) -> String {
        format!("{}:{}", self.ip_addr, self.transfer_port)
    }
}

/// Announcement message sent via UDP broadcast
/// Note: IP is NOT included - it's extracted from the UDP packet source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announcement {
    pub instance_id: Uuid,
    pub device_name: String,
    pub transfer_port: u16,
    pub version: String,
    pub fingerprint: String,
}

impl Announcement {
    pub fn new(
        instance_id: Uuid,
        device_name: String,
        transfer_port: u16,
        fingerprint: String,
    ) -> Self {
        Self {
            instance_id,
            device_name,
            transfer_port,
            version: crate::config::PROTOCOL_VERSION.to_string(),
            fingerprint,
        }
    }

    /// Convert announcement to peer with given IP address
    pub fn to_peer(&self, ip_addr: IpAddr) -> Peer {
        Peer::new(
            self.instance_id,
            self.device_name.clone(),
            ip_addr,
            self.transfer_port,
            self.fingerprint.clone(),
        )
    }
}
