use crate::error::{Result, RustDropError};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use tracing::info;

/// Represents the identity (certificate + key) for this instance
#[derive(Clone)]
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
        let subject_alt_names = vec![device_name.to_string(), "localhost".to_string()];

        let cert = generate_simple_self_signed(subject_alt_names).map_err(|e| {
            RustDropError::Certificate(format!("Failed to generate certificate: {}", e))
        })?;

        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let fingerprint = fingerprint_from_pem(&cert_pem)?;

        Ok(Self {
            cert_pem,
            key_pem,
            fingerprint,
        })
    }

    /// Load identity from PEM files
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = fs::read_to_string(cert_path).map_err(|e| {
            RustDropError::Certificate(format!("Failed to read certificate: {}", e))
        })?;

        let key_pem = fs::read_to_string(key_path)
            .map_err(|e| RustDropError::Certificate(format!("Failed to read key: {}", e)))?;

        let fingerprint = fingerprint_from_pem(&cert_pem)?;

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
            fs::create_dir_all(parent).map_err(|e| {
                RustDropError::Certificate(format!("Failed to create cert directory: {}", e))
            })?;
        }

        fs::write(cert_path, &self.cert_pem).map_err(|e| {
            RustDropError::Certificate(format!("Failed to write certificate: {}", e))
        })?;

        fs::write(key_path, &self.key_pem)
            .map_err(|e| RustDropError::Certificate(format!("Failed to write key: {}", e)))?;

        // Set restrictive permissions on key file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(key_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
                RustDropError::Certificate(format!("Failed to set key permissions: {}", e))
            })?;
        }

        info!("Saved identity to {:?}", cert_path);
        Ok(())
    }

    /// First bytes of the fingerprint, for display in lists and prompts
    pub fn short_fingerprint(&self) -> &str {
        short_fingerprint(&self.fingerprint)
    }
}

/// SHA-256 fingerprint of a DER-encoded certificate, hex-encoded.
///
/// This is the identifier peers broadcast and the value the TLS client pins the
/// presented certificate against, so it has to be a cryptographic hash: anything
/// weaker would let an attacker craft a certificate with a matching fingerprint.
pub fn fingerprint_from_der(cert_der: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert_der.as_ref());
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

/// SHA-256 fingerprint of the first certificate in a PEM string
pub fn fingerprint_from_pem(cert_pem: &str) -> Result<String> {
    use rustls_pemfile::certs;
    use std::io::BufReader;

    let mut reader = BufReader::new(cert_pem.as_bytes());

    match certs(&mut reader).next() {
        Some(Ok(cert_der)) => Ok(fingerprint_from_der(&cert_der)),
        _ => Err(RustDropError::Certificate(
            "No certificate found in PEM data".into(),
        )),
    }
}

/// Shorten a fingerprint for display
pub fn short_fingerprint(fingerprint: &str) -> &str {
    &fingerprint[..16.min(fingerprint.len())]
}
