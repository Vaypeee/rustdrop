use crate::error::{Result, RustDropError};
use crate::security::identity::{Identity, fingerprint_from_der};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme,
};
use rustls_pemfile::{certs, private_key};
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::debug;

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

/// Create a TLS connector that pins the peer's certificate fingerprint.
///
/// Peers use self-signed certificates, so there is no CA chain to walk. Instead
/// we trust the SHA-256 fingerprint the peer broadcast over UDP discovery: the
/// handshake only succeeds if the certificate presented hashes to that value and
/// the peer proves possession of the matching private key.
pub fn create_tls_connector(expected_fingerprint: &str) -> Result<TlsConnector> {
    let verifier = PinnedCertVerifier {
        expected_fingerprint: expected_fingerprint.to_ascii_lowercase(),
        provider: Arc::new(rustls::crypto::ring::default_provider()),
    };

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Load certificates from PEM string
fn load_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader).filter_map(|r| r.ok()).collect();

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

/// Accepts exactly one self-signed certificate: the one whose SHA-256
/// fingerprint matches the value announced by the peer we meant to reach.
#[derive(Debug)]
struct PinnedCertVerifier {
    expected_fingerprint: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let presented = fingerprint_from_der(end_entity);

        if presented == self.expected_fingerprint {
            debug!("Peer certificate matches pinned fingerprint");
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    // The fingerprint only proves which certificate was presented; certificates
    // are public, so we still let rustls check the handshake signature to prove
    // the peer actually holds the matching private key.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
