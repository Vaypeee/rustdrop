use crate::config::Settings;
use crate::error::{Result, RustDropError};
use crate::security::{Identity, create_tls_acceptor};
use crate::transfer::protocol::{Message, ProtocolError, TextMessage, TransferRequest, read_chunk};
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, info};

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
        let listener =
            TcpListener::bind(format!("0.0.0.0:{}", self.settings.transfer_port)).await?;

        info!("Receiver listening on port {}", self.settings.transfer_port);

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
    let mut tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| RustDropError::Tls(format!("TLS accept failed: {}", e)))?;

    debug!("TLS handshake complete");

    let msg = Message::read_from(&mut tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    match msg {
        Message::TransferRequest(request) => {
            handle_file_transfer(&mut tls_stream, request, settings, auto_accept).await
        }
        Message::TextMessage(message) => {
            handle_text_message(&mut tls_stream, message, auto_accept).await
        }
        _ => {
            let error = Message::TransferError {
                message: "Expected TransferRequest or TextMessage".into(),
            };
            let _ = error.write_to(&mut tls_stream).await;
            Err(RustDropError::Transfer("Unexpected message".into()))
        }
    }
}

async fn handle_file_transfer(
    tls_stream: &mut TlsStream<TcpStream>,
    request: TransferRequest,
    settings: &Settings,
    auto_accept: bool,
) -> Result<()> {
    info!(
        "Transfer request: '{}' ({}) from '{}'",
        request.filename,
        format_size(request.file_size),
        request.sender_name
    );

    let prompt = format!(
        "Accept '{}' ({}) from '{}'?",
        request.filename,
        format_size(request.file_size),
        request.sender_name
    );

    if !confirm(&prompt, auto_accept).await {
        info!("Transfer declined");
        Message::TransferReject {
            reason: "User declined".into(),
        }
        .write_to(tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;
        return Ok(());
    }

    Message::TransferAccept
        .write_to(tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    // Confirm (or report failure) so the sender knows the file is committed
    match receive_file(tls_stream, &request, &settings.download_dir).await {
        Ok(()) => {
            Message::TransferComplete
                .write_to(tls_stream)
                .await
                .map_err(protocol_to_rustdrop)?;
            Ok(())
        }
        Err(e) => {
            let _ = Message::TransferError {
                message: e.to_string(),
            }
            .write_to(tls_stream)
            .await;
            Err(e)
        }
    }
}

async fn handle_text_message(
    tls_stream: &mut TlsStream<TcpStream>,
    message: TextMessage,
    auto_accept: bool,
) -> Result<()> {
    info!("Incoming message from '{}'", message.sender_name);

    let prompt = format!("Accept a message from '{}'?", message.sender_name);

    if !confirm(&prompt, auto_accept).await {
        Message::TransferReject {
            reason: "User declined".into(),
        }
        .write_to(tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;
        return Ok(());
    }

    Message::TransferAccept
        .write_to(tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    display_text_message(&message.text, &message.sender_name);

    Message::TransferComplete
        .write_to(tls_stream)
        .await
        .map_err(protocol_to_rustdrop)?;

    Ok(())
}

async fn receive_file(
    stream: &mut TlsStream<TcpStream>,
    request: &TransferRequest,
    download_dir: &Path,
) -> Result<()> {
    tokio::fs::create_dir_all(download_dir).await?;

    // Pick a name that does not clobber an existing download
    let file_path = get_unique_path(download_dir, &request.filename).await;

    info!("Saving to {:?}", file_path);

    let mut file = File::create(&file_path).await?;
    let mut received: u64 = 0;
    let mut last_tenth = 0;

    loop {
        match read_chunk(stream).await {
            Ok(Some(chunk)) => {
                file.write_all(&chunk).await?;
                received += chunk.len() as u64;
                report_progress(received, request.file_size, &mut last_tenth);
            }
            Ok(None) => break,
            Err(e) => {
                // Do not leave a half-written file behind
                drop(file);
                let _ = tokio::fs::remove_file(&file_path).await;
                return Err(protocol_to_rustdrop(e));
            }
        }
    }

    file.flush().await?;

    if received != request.file_size {
        drop(file);
        let _ = tokio::fs::remove_file(&file_path).await;
        return Err(RustDropError::Transfer(format!(
            "Incomplete transfer: expected {} bytes, got {}",
            request.file_size, received
        )));
    }

    info!(
        "File '{}' received successfully ({})",
        request.filename,
        format_size(received)
    );

    Ok(())
}

/// Ask the user to confirm, unless running with --accept-all.
///
/// Reading a line blocks, so it goes on the blocking pool rather than stalling
/// the runtime while other transfers are in flight.
async fn confirm(prompt: &str, auto_accept: bool) -> bool {
    if auto_accept {
        info!("Auto-accepting");
        return true;
    }

    let prompt = prompt.to_string();

    tokio::task::spawn_blocking(move || {
        use std::io::{self, Write};

        print!("\n{} [y/N] ", prompt);
        let _ = io::stdout().flush();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return false;
        }

        matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
    })
    .await
    .unwrap_or(false)
}

const MAX_DISPLAY_LINES: usize = 10;

/// Display a text message in the terminal with formatting
fn display_text_message(content: &str, sender: &str) {
    let rule = "-".repeat(50);

    println!("\n{}", rule);
    println!("Message from {}:", sender);
    println!("{}", rule);

    let lines: Vec<&str> = content.lines().collect();

    for line in lines.iter().take(MAX_DISPLAY_LINES) {
        println!("{}", make_links_clickable(line));
    }

    if lines.len() > MAX_DISPLAY_LINES {
        println!("\n... ({} more lines)", lines.len() - MAX_DISPLAY_LINES);
    }

    println!("{}", rule);

    copy_urls_to_clipboard(content);
}

/// Copy any URLs found in the message to the clipboard
fn copy_urls_to_clipboard(content: &str) {
    let urls = extract_urls(content);
    if urls.is_empty() {
        return;
    }

    if let Ok(mut clipboard) = arboard::Clipboard::new()
        && clipboard.set_text(urls.join("\n")).is_ok()
    {
        if urls.len() == 1 {
            println!("Copied to clipboard: {}", urls[0]);
        } else {
            println!("Copied {} links to clipboard", urls.len());
        }
    }
}

/// Make URLs clickable in terminal using OSC 8 escape sequences
fn make_links_clickable(text: &str) -> String {
    url_pattern()
        .replace_all(text, |caps: &regex_lite::Captures| {
            let url = &caps[1];
            format!("\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\", url, url)
        })
        .to_string()
}

/// Extract all URLs from text
fn extract_urls(text: &str) -> Vec<String> {
    url_pattern()
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

fn url_pattern() -> regex_lite::Regex {
    regex_lite::Regex::new(r"(https?://[^\s]+)").expect("URL pattern is a valid regex")
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
        info!("Received {}%", tenth * 10);
    }
}

/// Human-readable byte count
fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];

    let mut size = bytes as f64;
    let mut unit = 0;

    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", size, UNITS[unit])
    }
}

/// Get a unique file path, appending (1), (2), etc. if the file exists
async fn get_unique_path(dir: &Path, filename: &str) -> PathBuf {
    let base_path = dir.join(filename);

    if !base_path.exists() {
        return base_path;
    }

    let stem = Path::new(filename)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| filename.to_string());

    let extension = Path::new(filename)
        .extension()
        .map(|s| format!(".{}", s.to_string_lossy()))
        .unwrap_or_default();

    for i in 1..1000 {
        let new_path = dir.join(format!("{} ({}){}", stem, i, extension));
        if !new_path.exists() {
            return new_path;
        }
    }

    // Fallback: timestamp suffix
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    dir.join(format!("{}_{}{}", stem, timestamp, extension))
}

fn protocol_to_rustdrop(e: ProtocolError) -> RustDropError {
    RustDropError::Transfer(e.to_string())
}
