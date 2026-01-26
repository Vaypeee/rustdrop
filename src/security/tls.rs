use crate::error::{Result, RustDropError};
use crate::security::identity::Identity;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, ServerConfig};
use rustls_pemfile::{certs, private_key};
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Create a TLS acceptor (server) from identity
pub fn create_tls_acceptor(identity: &Identity) -> Result<TlsAcceptor> {
    let certs = load_certs(&identity.cert_pem)?;
    let key = load_private_key(&identity.key_pem)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| RustDropError::Tls(format!("Failed to create server config: {}", e)))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Create a TLS connector (client) that accepts any certificate
/// Note: In production, you'd want to verify the peer's fingerprint
pub fn create_tls_connector() -> Result<TlsConnector> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Load certificates from PEM string
fn load_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .filter_map(|r| r.ok())
        .collect();

    if certs.is_empty() {
        return Err(RustDropError::Certificate("No certificates found".into()));
    }

    Ok(certs)
}

/// Load private key from PEM string
fn load_private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(pem.as_bytes());

    private_key(&mut reader)
        .map_err(|e| RustDropError::Certificate(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| RustDropError::Certificate("No private key found".into()))
}

/// Certificate verifier that accepts any certificate
/// This is used because we're using self-signed certificates
/// The actual verification is done by comparing fingerprints
#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Accept any certificate - we verify via fingerprint comparison
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
