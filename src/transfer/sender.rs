use crate::discovery::Peer;
use crate::error::{Result, RustDropError};
use crate::security::create_tls_connector;
use crate::transfer::protocol::{FileData, Message, ProtocolError, TransferRequest, CHUNK_SIZE};
use rustls::pki_types::ServerName;
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// Send a file to a peer
pub async fn send_file(
    peer: &Peer,
    file_path: &Path,
    sender_name: &str,
) -> Result<()> {
    // Get file info
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

    // Connect to peer
    let addr = peer.transfer_addr();
    let tcp_stream = TcpStream::connect(&addr).await.map_err(|e| {
        RustDropError::Network(format!("Failed to connect to {}: {}", addr, e))
    })?;

    debug!("Connected to {}", addr);

    // Establish TLS
    let connector = create_tls_connector()?;
    let server_name = ServerName::try_from("localhost".to_string())
        .map_err(|e| RustDropError::Tls(format!("Invalid server name: {}", e)))?;

    let mut tls_stream = connector.connect(server_name, tcp_stream).await.map_err(|e| {
        RustDropError::Tls(format!("TLS handshake failed: {}", e))
    })?;

    debug!("TLS connection established");

    // Send transfer request
    let request = Message::TransferRequest(TransferRequest {
        filename: filename.clone(),
        file_size,
        sender_name: sender_name.to_string(),
    });
    request.write_to(&mut tls_stream).await.map_err(protocol_to_rustdrop)?;

    debug!("Transfer request sent, waiting for response...");

    // Wait for accept/reject
    let response = Message::read_from(&mut tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    match response {
        Message::TransferAccept => {
            debug!("Transfer accepted");
        }
        Message::TransferReject { reason } => {
            return Err(RustDropError::Transfer(format!(
                "Transfer rejected: {}",
                reason
            )));
        }
        _ => {
            return Err(RustDropError::Transfer("Unexpected response".into()));
        }
    }

    // Send file data
    let file = File::open(file_path).await?;
    let mut reader = BufReader::new(file);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut offset: u64 = 0;
    let mut last_progress = 0;

    loop {
        let bytes_read = reader.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }

        let is_last = offset + bytes_read as u64 >= file_size;

        let chunk = Message::FileData(FileData {
            offset,
            data: buffer[..bytes_read].to_vec(),
            is_last,
        });

        chunk.write_to(&mut tls_stream).await.map_err(protocol_to_rustdrop)?;

        offset += bytes_read as u64;

        // Progress reporting
        let progress = (offset * 100 / file_size) as u8;
        if progress > last_progress && progress % 10 == 0 {
            info!("Sent {}%", progress);
            last_progress = progress;
        }
    }

    // Send completion message
    Message::TransferComplete
        .write_to(&mut tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    info!("File '{}' sent successfully!", filename);

    Ok(())
}

fn protocol_to_rustdrop(e: ProtocolError) -> RustDropError {
    RustDropError::Transfer(e.to_string())
}
