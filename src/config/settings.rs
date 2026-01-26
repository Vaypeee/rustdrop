use directories::ProjectDirs;
use std::path::PathBuf;

/// Default ports for RustDrop
pub const DEFAULT_DISCOVERY_PORT: u16 = 8765;
pub const DEFAULT_TRANSFER_PORT: u16 = 9000;

/// Discovery timing constants
pub const ANNOUNCE_INTERVAL_SECS: u64 = 2;
pub const PEER_TIMEOUT_SECS: u64 = 10;

/// Protocol version
pub const PROTOCOL_VERSION: &str = "1.0";

/// Application settings
#[derive(Debug, Clone)]
pub struct Settings {
    pub device_name: String,
    pub discovery_port: u16,
    pub transfer_port: u16,
    pub download_dir: PathBuf,
    pub certs_dir: PathBuf,
}

impl Default for Settings {
    fn default() -> Self {
        let device_name = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "Unknown".to_string());

        let (download_dir, certs_dir) = if let Some(proj_dirs) =
            ProjectDirs::from("com", "rustdrop", "RustDrop")
        {
            let data_dir = proj_dirs.data_dir().to_path_buf();
            let download = dirs_next::download_dir().unwrap_or_else(|| data_dir.join("downloads"));
            let certs = data_dir.join("certs");
            (download, certs)
        } else {
            let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("."));
            (home.join("Downloads"), home.join(".rustdrop/certs"))
        };

        Self {
            device_name,
            discovery_port: DEFAULT_DISCOVERY_PORT,
            transfer_port: DEFAULT_TRANSFER_PORT,
            download_dir,
            certs_dir,
        }
    }
}

impl Settings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_device_name(mut self, name: String) -> Self {
        self.device_name = name;
        self
    }

    pub fn with_transfer_port(mut self, port: u16) -> Self {
        self.transfer_port = port;
        self
    }

    pub fn with_download_dir(mut self, path: PathBuf) -> Self {
        self.download_dir = path;
        self
    }

    pub fn cert_path(&self) -> PathBuf {
        self.certs_dir.join("cert.pem")
    }

    pub fn key_path(&self) -> PathBuf {
        self.certs_dir.join("key.pem")
    }
}

mod dirs_next {
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }

    pub fn download_dir() -> Option<PathBuf> {
        home_dir().map(|h| h.join("Downloads"))
    }
}
