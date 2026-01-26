use crate::config::Settings;
use crate::error::{Result, RustDropError};
use crate::security::{create_tls_acceptor, Identity};
use crate::transfer::protocol::{Message, ProtocolError, TransferRequest};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, info, warn};

/// File transfer receiver (server)
pub struct Receiver {
    settings: Settings,
    identity: Identity,
    auto_accept: bool,
}

impl Receiver {
    pub fn new(settings: Settings, identity: Identity, auto_accept: bool) -> Self {
        Self {
            settings,
            identity,
            auto_accept,
        }
    }

    /// Start the receiver server
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.settings.transfer_port))
            .await?;

        info!(
            "Receiver listening on port {}",
            self.settings.transfer_port
        );

        let acceptor = create_tls_acceptor(&self.identity)?;

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            info!("Incoming connection from {}", addr);
                            let acceptor = acceptor.clone();
                            let settings = self.settings.clone();
                            let auto_accept = self.auto_accept;

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, acceptor, &settings, auto_accept).await {
                                    error!("Connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("Receiver shutting down");
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    settings: &Settings,
    auto_accept: bool,
) -> Result<()> {
    // TLS handshake
    let mut tls_stream = acceptor.accept(stream).await.map_err(|e| {
        RustDropError::Tls(format!("TLS accept failed: {}", e))
    })?;

    debug!("TLS handshake complete");

    // Read transfer request
    let msg = Message::read_from(&mut tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    let request = match msg {
        Message::TransferRequest(req) => req,
        _ => {
            let error = Message::TransferError {
                message: "Expected TransferRequest".into(),
            };
            let _ = error.write_to(&mut tls_stream).await;
            return Err(RustDropError::Transfer("Unexpected message".into()));
        }
    };

    info!(
        "Transfer request: '{}' ({} bytes) from '{}'",
        request.filename, request.file_size, request.sender_name
    );

    // Accept or reject (auto-accept for now, could prompt user)
    let accepted = if auto_accept {
        info!("Auto-accepting transfer");
        true
    } else {
        // In a real app, you'd prompt the user here
        info!("Auto-accepting transfer (interactive mode not implemented)");
        true
    };

    if !accepted {
        Message::TransferReject {
            reason: "User declined".into(),
        }
        .write_to(&mut tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;
        return Ok(());
    }

    Message::TransferAccept
        .write_to(&mut tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    // Receive file
    receive_file(&mut tls_stream, &request, &settings.download_dir).await?;

    Ok(())
}

async fn receive_file(
    stream: &mut TlsStream<TcpStream>,
    request: &TransferRequest,
    download_dir: &PathBuf,
) -> Result<()> {
    // Create download directory if needed
    tokio::fs::create_dir_all(download_dir).await?;

    // Create unique filename to avoid overwriting
    let file_path = get_unique_path(download_dir, &request.filename).await;

    info!("Saving to {:?}", file_path);

    let mut file = File::create(&file_path).await?;
    let mut received: u64 = 0;
    let mut last_progress = 0;

    loop {
        let msg = Message::read_from(stream)
            .await
            .map_err(protocol_to_rustdrop)?;

        match msg {
            Message::FileData(data) => {
                file.write_all(&data.data).await?;
                received += data.data.len() as u64;

                // Progress reporting
                if request.file_size > 0 {
                    let progress = (received * 100 / request.file_size) as u8;
                    if progress > last_progress && progress % 10 == 0 {
                        info!("Received {}%", progress);
                        last_progress = progress;
                    }
                }

                if data.is_last {
                    break;
                }
            }
            Message::TransferComplete => {
                break;
            }
            Message::TransferError { message } => {
                // Clean up partial file
                let _ = tokio::fs::remove_file(&file_path).await;
                return Err(RustDropError::Transfer(message));
            }
            _ => {
                warn!("Unexpected message during transfer");
            }
        }
    }

    file.flush().await?;

    info!(
        "File '{}' received successfully ({} bytes)",
        request.filename, received
    );

    // If it's a text message, display it in the terminal
    if request.filename == "rustdrop_message.txt" {
        if let Ok(content) = tokio::fs::read_to_string(&file_path).await {
            display_text_message(&content, &request.sender_name, &file_path);
        }
    }

    Ok(())
}

const MAX_DISPLAY_LINES: usize = 10;

/// Display a text message in the terminal with formatting
fn display_text_message(content: &str, sender: &str, file_path: &PathBuf) {
    println!("\n{}", "─".repeat(50));
    println!("📨 Message from {}:", sender);
    println!("{}", "─".repeat(50));

    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();

    // Display limited lines
    for line in lines.iter().take(MAX_DISPLAY_LINES) {
        let displayed = make_links_clickable(line);
        println!("{}", displayed);
    }

    if total_lines > MAX_DISPLAY_LINES {
        println!("\n... ({} lignes supplémentaires)", total_lines - MAX_DISPLAY_LINES);
        println!("📄 Fichier complet: {:?}", file_path);
    }

    println!("{}", "─".repeat(50));

    // Extract URLs and copy to clipboard
    let urls = extract_urls(content);
    if !urls.is_empty() {
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            let to_copy = if urls.len() == 1 {
                urls[0].clone()
            } else {
                urls.join("\n")
            };

            if clipboard.set_text(&to_copy).is_ok() {
                println!("📋 Copié dans le presse-papier: {}",
                    if urls.len() == 1 { &urls[0] } else { "(plusieurs liens)" });
            }
        }
    }
}

/// Make URLs clickable in terminal using OSC 8 escape sequence
fn make_links_clickable(text: &str) -> String {
    let url_pattern = regex_lite::Regex::new(r"(https?://[^\s]+)").unwrap();
    url_pattern.replace_all(text, |caps: &regex_lite::Captures| {
        let url = &caps[1];
        // OSC 8 hyperlink format: \x1b]8;;URL\x1b\\TEXT\x1b]8;;\x1b\\
        format!("\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\", url, url)
    }).to_string()
}

/// Extract all URLs from text
fn extract_urls(text: &str) -> Vec<String> {
    let url_pattern = regex_lite::Regex::new(r"(https?://[^\s]+)").unwrap();
    url_pattern.find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

/// Get a unique file path, appending (1), (2), etc. if file exists
async fn get_unique_path(dir: &PathBuf, filename: &str) -> PathBuf {
    let base_path = dir.join(filename);

    if !base_path.exists() {
        return base_path;
    }

    let stem = std::path::Path::new(filename)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| filename.to_string());

    let extension = std::path::Path::new(filename)
        .extension()
        .map(|s| format!(".{}", s.to_string_lossy()))
        .unwrap_or_default();

    for i in 1..1000 {
        let new_name = format!("{} ({}){}", stem, i, extension);
        let new_path = dir.join(&new_name);
        if !new_path.exists() {
            return new_path;
        }
    }

    // Fallback: use timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    dir.join(format!("{}_{}{}", stem, timestamp, extension))
}

fn protocol_to_rustdrop(e: ProtocolError) -> RustDropError {
    RustDropError::Transfer(e.to_string())
}
