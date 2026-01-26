use rustdrop::config::Settings;
use rustdrop::discovery::Peer;
use rustdrop::security::Identity;
use rustdrop::transfer::{send_file, Receiver};
use std::net::IpAddr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tokio::time::sleep;
use uuid::Uuid;

#[tokio::test]
async fn test_file_transfer() {
    // Create temp directories
    let sender_dir = TempDir::new().expect("Failed to create sender temp dir");
    let receiver_dir = TempDir::new().expect("Failed to create receiver temp dir");

    // Create test file
    let test_file = sender_dir.path().join("test.txt");
    let test_content = b"Hello, RustDrop! This is a test file.";
    fs::write(&test_file, test_content).await.expect("Failed to write test file");

    // Setup receiver
    let receiver_settings = Settings::new()
        .with_device_name("Receiver".to_string())
        .with_transfer_port(9100)
        .with_download_dir(receiver_dir.path().to_path_buf());

    let receiver_identity = Identity::generate("Receiver").expect("Failed to generate identity");

    let receiver = Receiver::new(receiver_settings.clone(), receiver_identity.clone(), true);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Start receiver
    let receiver_handle = tokio::spawn(async move {
        let _ = receiver.run(shutdown_rx).await;
    });

    // Wait for receiver to start
    sleep(Duration::from_millis(500)).await;

    // Create a peer pointing to the receiver
    let peer = Peer::new(
        Uuid::new_v4(),
        "Receiver".to_string(),
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        9100,
        receiver_identity.fingerprint.clone(),
    );

    // Send file
    let result = send_file(&peer, &test_file, "Sender").await;

    // Shutdown receiver
    let _ = shutdown_tx.send(true);
    receiver_handle.abort();

    // Check result
    assert!(result.is_ok(), "Transfer failed: {:?}", result.err());

    // Verify received file
    let received_file = receiver_dir.path().join("test.txt");
    let received_content = fs::read(&received_file).await.expect("Failed to read received file");
    assert_eq!(received_content, test_content);
}

#[tokio::test]
async fn test_large_file_transfer() {
    // Create temp directories
    let sender_dir = TempDir::new().expect("Failed to create sender temp dir");
    let receiver_dir = TempDir::new().expect("Failed to create receiver temp dir");

    // Create a larger test file (1MB)
    let test_file = sender_dir.path().join("large.bin");
    let test_content: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    fs::write(&test_file, &test_content).await.expect("Failed to write test file");

    // Setup receiver
    let receiver_settings = Settings::new()
        .with_device_name("Receiver".to_string())
        .with_transfer_port(9101)
        .with_download_dir(receiver_dir.path().to_path_buf());

    let receiver_identity = Identity::generate("Receiver").expect("Failed to generate identity");

    let receiver = Receiver::new(receiver_settings.clone(), receiver_identity.clone(), true);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Start receiver
    let receiver_handle = tokio::spawn(async move {
        let _ = receiver.run(shutdown_rx).await;
    });

    // Wait for receiver to start
    sleep(Duration::from_millis(500)).await;

    // Create a peer pointing to the receiver
    let peer = Peer::new(
        Uuid::new_v4(),
        "Receiver".to_string(),
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        9101,
        receiver_identity.fingerprint.clone(),
    );

    // Send file
    let result = send_file(&peer, &test_file, "Sender").await;

    // Shutdown receiver
    let _ = shutdown_tx.send(true);
    receiver_handle.abort();

    // Check result
    assert!(result.is_ok(), "Transfer failed: {:?}", result.err());

    // Verify received file
    let received_file = receiver_dir.path().join("large.bin");
    let received_content = fs::read(&received_file).await.expect("Failed to read received file");
    assert_eq!(received_content.len(), test_content.len());
    assert_eq!(received_content, test_content);
}
