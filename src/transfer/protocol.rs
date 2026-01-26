use serde::{Deserialize, Serialize};

/// Protocol message types for file transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    /// Request to send a file
    TransferRequest(TransferRequest),

    /// Accept the transfer
    TransferAccept,

    /// Reject the transfer
    TransferReject { reason: String },

    /// File data chunk
    FileData(FileData),

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

/// File data chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileData {
    pub offset: u64,
    pub data: Vec<u8>,
    pub is_last: bool,
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
    pub async fn read_from<R: tokio::io::AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<Self, ProtocolError> {
        // Read length prefix
        let mut len_bytes = [0u8; 4];
        reader.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Sanity check - max 100MB message
        if len > 100 * 1024 * 1024 {
            return Err(ProtocolError::MessageTooLarge(len));
        }

        // Read message body
        let mut body = vec![0u8; len];
        reader.read_exact(&mut body).await?;

        // Deserialize
        let msg: Message = serde_json::from_slice(&body)?;
        Ok(msg)
    }

    /// Write a message to a stream
    pub async fn write_to<W: tokio::io::AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), ProtocolError> {
        let bytes = self.to_bytes()?;
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        Ok(())
    }
}

/// Protocol-specific errors
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Message too large: {0} bytes")]
    MessageTooLarge(usize),

    #[error("Unexpected message type")]
    UnexpectedMessage,

    #[error("Transfer rejected: {0}")]
    Rejected(String),
}

/// Chunk size for file transfers (64KB)
pub const CHUNK_SIZE: usize = 64 * 1024;
