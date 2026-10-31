#![allow(dead_code)]

use rustdrop::config::Settings;
use rustdrop::security::Identity;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// A receiver ready to run: settings, identity, and the directory downloads land in.
///
/// The `TempDir` is returned so the caller keeps it alive; dropping it deletes
/// the download directory.
pub struct TestReceiver {
    pub settings: Settings,
    pub identity: Identity,
    pub download_dir: TempDir,
}

/// Build a receiver bound to `port`, downloading into a fresh temp directory
pub fn test_receiver(name: &str, port: u16) -> TestReceiver {
    let download_dir = TempDir::new().expect("Failed to create temp dir");

    let settings = Settings::new()
        .with_device_name(name.to_string())
        .with_transfer_port(port)
        .with_download_dir(download_dir.path().to_path_buf());

    let identity = Identity::generate(name).expect("Failed to generate identity");

    TestReceiver {
        settings,
        identity,
        download_dir,
    }
}

/// Create a test file of `size` bytes with a repeating byte pattern
pub async fn create_test_file(dir: &Path, name: &str, size: usize) -> PathBuf {
    use tokio::fs;
    use tokio::io::AsyncWriteExt;

    fs::create_dir_all(dir)
        .await
        .expect("Failed to create test dir");
    let path = dir.join(name);

    let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    let mut file = fs::File::create(&path)
        .await
        .expect("Failed to create test file");
    file.write_all(&content)
        .await
        .expect("Failed to write test file");

    path
}

/// Install the rustls crypto provider once per test binary.
///
/// Each integration test file is its own process, but several `#[tokio::test]`
/// functions share it, so the second call would fail without this guard.
pub fn install_crypto_provider() {
    use std::sync::Once;

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
