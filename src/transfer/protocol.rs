use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Control messages exchanged before and after the raw file stream.
///
/// Control messages are JSON for readability and forward compatibility; the file
/// payload itself travels as raw binary frames (see [`write_chunk`]), because
/// JSON-encoding a `Vec<u8>` would inflate it roughly fourfold.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    /// Request to send a file
    TransferRequest(TransferRequest),

    /// A short text message, delivered without touching the filesystem
    TextMessage(TextMessage),

    /// Accept the transfer
    TransferAccept,

    /// Reject the transfer
    TransferReject { reason: String },

    /// Transfer complete
    TransferComplete,

    /// Error during transfer
    TransferError { message: String },
}

/// File transfer request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub filename: String,
    pub file_size: u64,
    pub sender_name: String,
}

/// Text message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextMessage {
    pub text: String,
    pub sender_name: String,
}

impl Message {
    /// Serialize message to bytes (length-prefixed)
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let json = serde_json::to_vec(self)?;
        let len = json.len() as u32;
        let mut bytes = Vec::with_capacity(4 + json.len());
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend(json);
        Ok(bytes)
    }

    /// Read a message from a stream
    pub async fn read_from<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Self, ProtocolError> {
        let len = read_frame_len(reader).await?;

        if len > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge(len));
        }

        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).await?;

        let msg: Message = serde_json::from_slice(&body)?;
        Ok(msg)
    }

    /// Write a message to a stream
    pub async fn write_to<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), ProtocolError> {
        let bytes = self.to_bytes()?;
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        Ok(())
    }
}

/// Read a 4-byte big-endian frame length.
async fn read_frame_len<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<usize, ProtocolError> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    Ok(u32::from_be_bytes(len_bytes) as usize)
}

/// Write one raw data frame: a 4-byte big-endian length followed by the bytes.
///
/// An empty slice marks the end of the stream, so callers must not pass one for
/// actual data.
pub async fn write_chunk<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    chunk: &[u8],
) -> Result<(), ProtocolError> {
    writer
        .write_all(&(chunk.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(chunk).await?;
    Ok(())
}

/// Write the zero-length frame that terminates the data stream.
pub async fn write_end_of_stream<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
) -> Result<(), ProtocolError> {
    writer.write_all(&0u32.to_be_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one raw data frame, or `None` once the end-of-stream frame arrives.
pub async fn read_chunk<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    let len = read_frame_len(reader).await?;

    if len == 0 {
        return Ok(None);
    }

    if len > MAX_CHUNK_SIZE {
        return Err(ProtocolError::MessageTooLarge(len));
    }

    let mut chunk = vec![0u8; len];
    reader.read_exact(&mut chunk).await?;
    Ok(Some(chunk))
}

/// Protocol-specific errors
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Frame too large: {0} bytes")]
    MessageTooLarge(usize),

    #[error("Unexpected message type")]
    UnexpectedMessage,

    #[error("Transfer rejected: {0}")]
    Rejected(String),
}

/// Chunk size for file transfers (64KB)
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Largest control message we are willing to buffer (1MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Largest data frame we are willing to buffer, four times what we send so a
/// future version can raise [`CHUNK_SIZE`] without breaking older receivers.
pub const MAX_CHUNK_SIZE: usize = 4 * CHUNK_SIZE;
