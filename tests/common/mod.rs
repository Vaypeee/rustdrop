use rustdrop::config::Settings;
use rustdrop::security::Identity;
use std::path::PathBuf;
use tempfile::TempDir;

/// Create test settings with a temporary directory
pub fn create_test_settings(port: u16) -> (Settings, TempDir) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let settings = Settings::new()
        .with_device_name(format!("test-device-{}", port))
        .with_transfer_port(port)
        .with_download_dir(temp_dir.path().join("downloads"));

    (settings, temp_dir)
}

/// Create a test identity
pub fn create_test_identity(settings: &Settings) -> Identity {
    Identity::load_or_generate(
        &settings.cert_path(),
        &settings.key_path(),
        &settings.device_name,
    )
    .expect("Failed to create test identity")
}

/// Create a test file with random content
pub async fn create_test_file(dir: &PathBuf, name: &str, size: usize) -> PathBuf {
    use tokio::fs;
    use tokio::io::AsyncWriteExt;

    fs::create_dir_all(dir).await.expect("Failed to create test dir");
    let path = dir.join(name);

    let content: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    let mut file = fs::File::create(&path).await.expect("Failed to create test file");
    file.write_all(&content).await.expect("Failed to write test file");

    path
}
