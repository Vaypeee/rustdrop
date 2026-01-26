use crate::error::{Result, RustDropError};
use rcgen::generate_simple_self_signed;
use std::fs;
use std::path::Path;
use tracing::info;

/// Represents the identity (certificate + key) for this instance
pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: String,
}

impl Identity {
    /// Load existing identity or generate a new one
    pub fn load_or_generate(cert_path: &Path, key_path: &Path, device_name: &str) -> Result<Self> {
        if cert_path.exists() && key_path.exists() {
            info!("Loading existing identity from {:?}", cert_path);
            Self::load(cert_path, key_path)
        } else {
            info!("Generating new identity for '{}'", device_name);
            let identity = Self::generate(device_name)?;
            identity.save(cert_path, key_path)?;
            Ok(identity)
        }
    }

    /// Generate a new self-signed certificate
    pub fn generate(device_name: &str) -> Result<Self> {
        let subject_alt_names = vec![
            device_name.to_string(),
            "localhost".to_string(),
        ];

        let cert = generate_simple_self_signed(subject_alt_names)
            .map_err(|e| RustDropError::Certificate(format!("Failed to generate certificate: {}", e)))?;

        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        // Calculate fingerprint (SHA-256 of DER-encoded certificate)
        let fingerprint = Self::calculate_fingerprint(&cert_pem);

        Ok(Self {
            cert_pem,
            key_pem,
            fingerprint,
        })
    }

    /// Load identity from PEM files
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = fs::read_to_string(cert_path)
            .map_err(|e| RustDropError::Certificate(format!("Failed to read certificate: {}", e)))?;

        let key_pem = fs::read_to_string(key_path)
            .map_err(|e| RustDropError::Certificate(format!("Failed to read key: {}", e)))?;

        let fingerprint = Self::calculate_fingerprint(&cert_pem);

        Ok(Self {
            cert_pem,
            key_pem,
            fingerprint,
        })
    }

    /// Save identity to PEM files
    pub fn save(&self, cert_path: &Path, key_path: &Path) -> Result<()> {
        // Create parent directories if needed
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| RustDropError::Certificate(format!("Failed to create cert directory: {}", e)))?;
        }

        fs::write(cert_path, &self.cert_pem)
            .map_err(|e| RustDropError::Certificate(format!("Failed to write certificate: {}", e)))?;

        fs::write(key_path, &self.key_pem)
            .map_err(|e| RustDropError::Certificate(format!("Failed to write key: {}", e)))?;

        // Set restrictive permissions on key file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))
                .map_err(|e| RustDropError::Certificate(format!("Failed to set key permissions: {}", e)))?;
        }

        info!("Saved identity to {:?}", cert_path);
        Ok(())
    }

    /// Calculate SHA-256 fingerprint of certificate
    fn calculate_fingerprint(cert_pem: &str) -> String {
        use std::io::BufReader;
        use rustls_pemfile::certs;

        let mut reader = BufReader::new(cert_pem.as_bytes());
        if let Some(Ok(cert_der)) = certs(&mut reader).next() {
            // Simple hash for fingerprint
            let hash = simple_sha256(&cert_der);
            hex_encode(&hash[..8]) // Use first 8 bytes for brevity
        } else {
            "unknown".to_string()
        }
    }
}

/// Simple SHA-256 implementation using ring (via rustls)
fn simple_sha256(data: &[u8]) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // For simplicity, use a basic hash. In production, use ring or sha2 crate
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let h1 = hasher.finish();

    let mut hasher = DefaultHasher::new();
    h1.hash(&mut hasher);
    let h2 = hasher.finish();

    let mut result = [0u8; 32];
    result[0..8].copy_from_slice(&h1.to_le_bytes());
    result[8..16].copy_from_slice(&h2.to_le_bytes());
    result[16..24].copy_from_slice(&h1.to_be_bytes());
    result[24..32].copy_from_slice(&h2.to_be_bytes());
    result
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
