use rustdrop::config::Settings;
use rustdrop::discovery::{Announcement, DiscoveryService, Peer};
use rustdrop::security::Identity;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

mod common;

#[test]
fn peer_exposes_its_transfer_address() {
    let peer = Peer::new(
        Uuid::new_v4(),
        "Test-Device".to_string(),
        "192.168.1.100".parse::<IpAddr>().unwrap(),
        9000,
        "abc123".to_string(),
    );

    assert_eq!(peer.device_name, "Test-Device");
    assert_eq!(peer.transfer_addr(), "192.168.1.100:9000");
    assert!(!peer.is_expired(10), "a freshly seen peer is not expired");
}

#[test]
fn peer_expires_once_its_timeout_elapses() {
    let peer = Peer::new(
        Uuid::new_v4(),
        "Test-Device".to_string(),
        "192.168.1.100".parse::<IpAddr>().unwrap(),
        9000,
        "abc123".to_string(),
    );

    assert!(!peer.is_expired(0), "just seen, so nothing has elapsed yet");

    std::thread::sleep(Duration::from_millis(1100));

    assert!(peer.is_expired(0), "a second has elapsed since it was seen");
    assert!(!peer.is_expired(3600), "still within a longer timeout");
}

#[test]
fn announcement_survives_a_serialization_round_trip() {
    let id = Uuid::new_v4();
    let announcement = Announcement::new(id, "Laptop".to_string(), 9000, "deadbeef".to_string());

    let bytes = serde_json::to_vec(&announcement).expect("announcement serializes");
    let decoded: Announcement = serde_json::from_slice(&bytes).expect("announcement decodes");

    assert_eq!(decoded.instance_id, id);
    assert_eq!(decoded.device_name, "Laptop");
    assert_eq!(decoded.transfer_port, 9000);
    assert_eq!(decoded.fingerprint, "deadbeef");
}

#[test]
fn announcement_becomes_a_peer_with_the_source_ip() {
    let announcement = Announcement::new(
        Uuid::new_v4(),
        "Laptop".to_string(),
        9000,
        "deadbeef".to_string(),
    );

    // The IP comes from the UDP packet, never from the payload
    let ip: IpAddr = "10.0.0.5".parse().unwrap();
    let peer = announcement.to_peer(ip);

    assert_eq!(peer.ip_addr, ip);
    assert_eq!(peer.transfer_addr(), "10.0.0.5:9000");
}

/// End-to-end discovery over a real UDP broadcast.
///
/// Ignored by default: it needs a network interface that allows broadcast and a
/// free discovery port, neither of which is guaranteed in CI. Run it with
/// `cargo test -- --ignored` on a real machine.
#[tokio::test]
#[ignore]
async fn two_instances_discover_each_other() {
    common::install_crypto_provider();

    let settings_a = Settings::new()
        .with_device_name("Device-A".to_string())
        .with_transfer_port(9001);
    let settings_b = Settings::new()
        .with_device_name("Device-B".to_string())
        .with_transfer_port(9002);

    let identity_a = Identity::generate("Device-A").expect("identity");
    let identity_b = Identity::generate("Device-B").expect("identity");

    let discovery_a = DiscoveryService::new(&settings_a, identity_a.fingerprint.clone());
    let discovery_b = DiscoveryService::new(&settings_b, identity_b.fingerprint.clone());

    let peers_a = discovery_a.peers();

    let handle_a = tokio::spawn(async move {
        let _ = discovery_a.run().await;
    });
    let handle_b = tokio::spawn(async move {
        let _ = discovery_b.run().await;
    });

    sleep(Duration::from_secs(5)).await;

    let found: Vec<Peer> = peers_a.read().await.values().cloned().collect();

    handle_a.abort();
    handle_b.abort();

    assert!(
        found.iter().any(|p| p.device_name == "Device-B"),
        "Device-A should have discovered Device-B, saw: {:?}",
        found.iter().map(|p| &p.device_name).collect::<Vec<_>>()
    );
}
