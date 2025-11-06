//! DNS packet parser
//!
//! Provides safe DNS packet parsing using the trust-dns-proto library.
//! Replaces manual C parsing from rfc1035.c with memory-safe Rust implementation.

use trust_dns_proto::op::{Message, Query};
use trust_dns_proto::serialize::binary::BinDecodable;

/// Type alias for DNS message (parsed packet)
pub type DnsMessage = Message;

/// Type alias for DNS question
pub type DnsQuestion = Query;

/// DNS packet parser wrapper
pub struct DnsParser;

impl DnsParser {
    /// Parse a DNS packet from raw bytes
    ///
    /// This is a wrapper around `parse_dns_packet` for use with the `DnsParser` type.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed, truncated, or violates DNS protocol constraints.
    pub fn parse(data: &[u8]) -> Result<DnsMessage, Box<dyn std::error::Error>> {
        parse_dns_packet(data)
    }
}

/// Parse a DNS packet from raw bytes
///
/// This function provides a safe wrapper around trust-dns-proto's Message parsing.
/// It performs comprehensive validation and bounds checking to prevent buffer overflows
/// and malformed packet handling.
///
/// # Arguments
///
/// * `data` - Raw DNS packet bytes to parse
///
/// # Returns
///
/// Returns Ok(Message) containing the parsed DNS message on success.
/// Returns Err if the packet is malformed, truncated, or violates DNS protocol constraints.
///
/// # Errors
///
/// Returns an error if:
/// - Packet is too short (< 12 bytes for DNS header)
/// - Packet format is invalid
/// - Label compression pointers are invalid
/// - Question/answer sections are malformed
///
/// # Example
///
/// ```no_run
/// use dnsmasq::dns::parser::parse_dns_packet;
///
/// let packet_data = vec![
///     0x12, 0x34, // ID
///     0x01, 0x00, // Flags: standard query
///     0x00, 0x01, // Questions: 1
///     0x00, 0x00, // Answers: 0
///     0x00, 0x00, // Authority: 0
///     0x00, 0x00, // Additional: 0
/// ];
///
/// match parse_dns_packet(&packet_data) {
///     Ok(message) => {
///         println!("Parsed DNS message with ID: {}", message.id());
///     }
///     Err(e) => {
///         eprintln!("Failed to parse DNS packet: {}", e);
///     }
/// }
/// ```
pub fn parse_dns_packet(data: &[u8]) -> Result<Message, Box<dyn std::error::Error>> {
    // Minimum DNS message size is 12 bytes (header only)
    if data.len() < 12 {
        return Err("DNS packet too short: minimum 12 bytes required".into());
    }
    
    // Use trust-dns-proto's safe parser which handles:
    // - Bounds checking on all reads
    // - Label compression pointer validation
    // - Maximum name length enforcement (255 bytes)
    // - Maximum label length enforcement (63 bytes)
    // - Circular pointer detection in compression
    let message = Message::from_bytes(data)?;
    
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_empty_packet_fails() {
        let result = parse_dns_packet(&[]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_parse_short_packet_fails() {
        let short_packet = vec![0x12, 0x34, 0x01, 0x00]; // Only 4 bytes
        let result = parse_dns_packet(&short_packet);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_parse_minimal_valid_packet() {
        // Minimal valid DNS query packet (12 byte header with no questions)
        let packet = vec![
            0x12, 0x34, // ID
            0x00, 0x00, // Flags: standard query
            0x00, 0x00, // Questions: 0
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
        ];
        
        let result = parse_dns_packet(&packet);
        assert!(result.is_ok());
        
        if let Ok(message) = result {
            assert_eq!(message.id(), 0x1234);
        }
    }
    
    #[test]
    fn test_parse_malformed_packet_fails() {
        // Packet with invalid question section
        let packet = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // Questions: 1 (but no question data follows)
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Missing question section data
        ];
        
        let result = parse_dns_packet(&packet);
        assert!(result.is_err());
    }
}
