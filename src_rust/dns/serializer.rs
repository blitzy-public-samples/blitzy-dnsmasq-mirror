//! DNS packet serialization
//!
//! Provides safe DNS packet serialization with automatic buffer management.
//! Replaces manual C serialization from rfc1035.c with memory-safe Rust implementation.

use trust_dns_proto::op::Message;

/// DNS packet serialization error
#[derive(Debug)]
pub enum SerializationError {
    /// Buffer too small for packet
    BufferTooSmall,
    /// Invalid packet structure
    InvalidPacket(String),
    /// Encoding error
    EncodingError(String),
}

impl std::fmt::Display for SerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SerializationError::BufferTooSmall => write!(f, "Buffer too small for DNS packet"),
            SerializationError::InvalidPacket(msg) => write!(f, "Invalid packet: {}", msg),
            SerializationError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
        }
    }
}

impl std::error::Error for SerializationError {}

/// DNS packet serializer
pub struct DnsSerializer;

impl DnsSerializer {
    /// Serialize a DNS message to bytes
    ///
    /// # Arguments
    ///
    /// * `message` - The DNS message to serialize
    ///
    /// # Returns
    ///
    /// Returns Ok(Vec<u8>) containing the serialized packet on success.
    /// Returns Err(SerializationError) if serialization fails.
    pub fn serialize(message: &Message) -> Result<Vec<u8>, SerializationError> {
        message
            .to_vec()
            .map_err(|e| SerializationError::EncodingError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns_proto::op::{Message, MessageType, OpCode};
    
    #[test]
    fn test_serialize_empty_message() {
        let message = Message::new();
        let result = DnsSerializer::serialize(&message);
        assert!(result.is_ok());
        
        if let Ok(bytes) = result {
            assert!(bytes.len() >= 12); // At least header size
        }
    }
    
    #[test]
    fn test_serialize_query() {
        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        
        let result = DnsSerializer::serialize(&message);
        assert!(result.is_ok());
        
        if let Ok(bytes) = result {
            // Check message ID in first two bytes (big-endian)
            assert_eq!(bytes[0], 0x12);
            assert_eq!(bytes[1], 0x34);
        }
    }
}
