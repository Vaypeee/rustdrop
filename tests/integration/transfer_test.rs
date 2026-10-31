use rustdrop::discovery::Peer;
use rustdrop::transfer::{Receiver, send_file, send_text};
use std::net::IpAddr;
use std::time::Duration;
use tokio::fs;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use uuid::Uuid;

mod common;

use common::{TestReceiver, create_test_file, install_crypto_provider, test_receiver};

/// Start a receiver in the background and build the `Peer` pointing at it
async fn start_receiver(
    name: &str,
    port: u16,
) -> (TestReceiver, Peer, watch::Sender<bool>, JoinHandle<()>) {
    install_crypto_provider();

    let test_receiver = test_receiver(name, port);

    let peer = Peer::new(
        Uuid::new_v4(),
        name.to_string(),
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        port,
        test_receiver.identity.fingerprint.clone(),
    );

    let receiver = Receiver::new(
        test_receiver.settings.clone(),
        test_receiver.identity.clone(),
        true,
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = tokio::spawn(async move {
        let _ = receiver.run(shutdown_rx).await;
    });

    // Give the listener a moment to bind
    sleep(Duration::from_millis(500)).await;

    (test_receiver, peer, shutdown_tx, handle)
}

#[tokio::test]
async fn transfers_a_small_file_intact() {
    let (receiver, peer, shutdown_tx, handle) = start_receiver("Receiver-Small", 9100).await;

    let source_dir = tempfile::TempDir::new().unwrap();
    let test_file = source_dir.path().join("test.txt");
    let test_content = b"Hello, RustDrop! This is a test file.";
    fs::write(&test_file, test_content).await.unwrap();

    let result = send_file(&peer, &test_file, "Sender").await;

    let _ = shutdown_tx.send(true);
    handle.abort();

    assert!(result.is_ok(), "Transfer failed: {:?}", result.err());

    let received = fs::read(receiver.download_dir.path().join("test.txt"))
        .await
        .expect("received file exists");
    assert_eq!(received, test_content);
}

#[tokio::test]
async fn transfers_a_file_larger_than_one_chunk() {
    let (receiver, peer, shutdown_tx, handle) = start_receiver("Receiver-Large", 9101).await;

    let source_dir = tempfile::TempDir::new().unwrap();
    // 1MB spans many 64KB chunks, so this exercises the framing loop
    let (test_file, expected) = create_test_file(source_dir.path(), "large.bin", 1024 * 1024).await;

    let result = send_file(&peer, &test_file, "Sender").await;

    let _ = shutdown_tx.send(true);
    handle.abort();

    assert!(result.is_ok(), "Transfer failed: {:?}", result.err());

    let received = fs::read(receiver.download_dir.path().join("large.bin"))
        .await
        .expect("received file exists");
    assert_eq!(received.len(), expected.len());
    assert_eq!(received, expected);
}

#[tokio::test]
async fn transfers_an_empty_file() {
    let (receiver, peer, shutdown_tx, handle) = start_receiver("Receiver-Empty", 9102).await;

    let source_dir = tempfile::TempDir::new().unwrap();
    let test_file = source_dir.path().join("empty.txt");
    fs::write(&test_file, b"").await.unwrap();

    let result = send_file(&peer, &test_file, "Sender").await;

    let _ = shutdown_tx.send(true);
    handle.abort();

    assert!(result.is_ok(), "Transfer failed: {:?}", result.err());
    assert_eq!(
        fs::read(receiver.download_dir.path().join("empty.txt"))
            .await
            .expect("received file exists")
            .len(),
        0
    );
}

#[tokio::test]
async fn a_second_file_of_the_same_name_does_not_overwrite_the_first() {
    let (receiver, peer, shutdown_tx, handle) = start_receiver("Receiver-Dup", 9103).await;

    let source_dir = tempfile::TempDir::new().unwrap();
    let test_file = source_dir.path().join("dup.txt");

    fs::write(&test_file, b"first").await.unwrap();
    send_file(&peer, &test_file, "Sender").await.unwrap();

    fs::write(&test_file, b"second").await.unwrap();
    send_file(&peer, &test_file, "Sender").await.unwrap();

    let _ = shutdown_tx.send(true);
    handle.abort();

    let dir = receiver.download_dir.path();
    assert_eq!(fs::read(dir.join("dup.txt")).await.unwrap(), b"first");
    assert_eq!(fs::read(dir.join("dup (1).txt")).await.unwrap(), b"second");
}

#[tokio::test]
async fn delivers_a_text_message_without_writing_a_file() {
    let (receiver, peer, shutdown_tx, handle) = start_receiver("Receiver-Text", 9104).await;

    let result = send_text(&peer, "hello from the other side", "Sender").await;

    let _ = shutdown_tx.send(true);
    handle.abort();

    assert!(result.is_ok(), "Text message failed: {:?}", result.err());

    let entries = std::fs::read_dir(receiver.download_dir.path())
        .map(|dir| dir.count())
        .unwrap_or(0);
    assert_eq!(entries, 0, "a text message must not land on disk");
}

/// The security property the whole design rests on: a peer whose certificate
/// does not match the announced fingerprint must not be able to receive data.
#[tokio::test]
async fn rejects_a_peer_whose_certificate_does_not_match_its_fingerprint() {
    let (_receiver, mut peer, shutdown_tx, handle) = start_receiver("Receiver-Mitm", 9105).await;

    // Same address, but the fingerprint we were told to expect belongs to
    // someone else, as it would if an attacker had taken over the port.
    peer.fingerprint = "00".repeat(32);

    let source_dir = tempfile::TempDir::new().unwrap();
    let test_file = source_dir.path().join("secret.txt");
    fs::write(&test_file, b"secret").await.unwrap();

    let result = send_file(&peer, &test_file, "Sender").await;

    let _ = shutdown_tx.send(true);
    handle.abort();

    assert!(
        result.is_err(),
        "the handshake must fail on a fingerprint mismatch"
    );
}
