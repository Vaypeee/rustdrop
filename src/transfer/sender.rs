use crate::discovery::Peer;
use crate::error::{Result, RustDropError};
use crate::security::create_tls_connector;
use crate::transfer::protocol::{
    CHUNK_SIZE, Message, ProtocolError, TextMessage, TransferRequest, write_chunk,
    write_end_of_stream,
};
use rustls::pki_types::ServerName;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tracing::{debug, info};

/// Send a file to a peer
pub async fn send_file(peer: &Peer, file_path: &Path, sender_name: &str) -> Result<()> {
    let filename = file_path
        .file_name()
        .ok_or_else(|| RustDropError::Transfer("Invalid file path".into()))?
        .to_string_lossy()
        .to_string();

    let metadata = tokio::fs::metadata(file_path).await?;
    let file_size = metadata.len();

    info!(
        "Sending '{}' ({} bytes) to '{}'",
        filename, file_size, peer.device_name
    );

    let mut tls_stream = connect(peer).await?;

    let request = Message::TransferRequest(TransferRequest {
        filename: filename.clone(),
        file_size,
        sender_name: sender_name.to_string(),
    });
    request
        .write_to(&mut tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    debug!("Transfer request sent, waiting for response...");
    await_acceptance(&mut tls_stream).await?;

    // Stream the file as raw binary frames
    let file = File::open(file_path).await?;
    let mut reader = BufReader::new(file);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut sent: u64 = 0;
    let mut last_tenth = 0;

    loop {
        let bytes_read = reader.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }

        write_chunk(&mut tls_stream, &buffer[..bytes_read])
            .await
            .map_err(protocol_to_rustdrop)?;

        sent += bytes_read as u64;
        report_progress(sent, file_size, &mut last_tenth);
    }

    write_end_of_stream(&mut tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    // Only report success once the receiver confirms the file is on its disk
    await_completion(&mut tls_stream).await?;

    info!("File '{}' sent successfully!", filename);

    Ok(())
}

/// Send a short text message to a peer
pub async fn send_text(peer: &Peer, text: &str, sender_name: &str) -> Result<()> {
    info!("Sending message to '{}'", peer.device_name);

    let mut tls_stream = connect(peer).await?;

    let message = Message::TextMessage(TextMessage {
        text: text.to_string(),
        sender_name: sender_name.to_string(),
    });
    message
        .write_to(&mut tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    await_acceptance(&mut tls_stream).await?;
    await_completion(&mut tls_stream).await?;

    info!("Message delivered to '{}'", peer.device_name);

    Ok(())
}

/// Open a TLS connection to a peer, pinned to the fingerprint it announced
async fn connect(peer: &Peer) -> Result<TlsStream<TcpStream>> {
    let addr = peer.transfer_addr();
    let tcp_stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| RustDropError::Network(format!("Failed to connect to {}: {}", addr, e)))?;

    debug!("Connected to {}", addr);

    let connector = create_tls_connector(&peer.fingerprint)?;

    // The certificate is self-signed and pinned by fingerprint, so the SNI name
    // is a formality the verifier ignores.
    let server_name = ServerName::try_from("localhost".to_string())
        .map_err(|e| RustDropError::Tls(format!("Invalid server name: {}", e)))?;

    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| {
            RustDropError::Tls(format!(
                "TLS handshake with '{}' failed (certificate does not match the announced \
                 fingerprint, or the peer is unreachable): {}",
                peer.device_name, e
            ))
        })?;

    debug!("TLS connection established");

    Ok(tls_stream)
}

/// Wait for the peer to accept or reject the transfer
async fn await_acceptance(stream: &mut TlsStream<TcpStream>) -> Result<()> {
    let response = Message::read_from(stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    match response {
        Message::TransferAccept => {
            debug!("Transfer accepted");
            Ok(())
        }
        Message::TransferReject { reason } => Err(RustDropError::Transfer(format!(
            "Transfer rejected: {}",
            reason
        ))),
        Message::TransferError { message } => Err(RustDropError::Transfer(message)),
        _ => Err(RustDropError::Transfer("Unexpected response".into())),
    }
}

/// Wait for the receiver to confirm it committed the transfer
async fn await_completion(stream: &mut TlsStream<TcpStream>) -> Result<()> {
    let response = Message::read_from(stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    match response {
        Message::TransferComplete => Ok(()),
        Message::TransferError { message } => Err(RustDropError::Transfer(message)),
        _ => Err(RustDropError::Transfer(
            "Unexpected response while waiting for completion".into(),
        )),
    }
}

/// Log transfer progress once per 10% crossed.
///
/// Chunks rarely land on an exact multiple of ten, so this tracks which tenth
/// of the file is done rather than testing the percentage for divisibility.
fn report_progress(done: u64, total: u64, last_tenth: &mut u8) {
    if total == 0 {
        return;
    }

    let tenth = (done * 10 / total) as u8;
    if tenth > *last_tenth {
        *last_tenth = tenth;
        info!("Sent {}%", tenth * 10);
    }
}

fn protocol_to_rustdrop(e: ProtocolError) -> RustDropError {
    RustDropError::Transfer(e.to_string())
}
