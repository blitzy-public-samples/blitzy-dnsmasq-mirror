//! EDNS0 (Extension Mechanisms for DNS) support
//!
//! Implements EDNS0 per RFC 6891, replacing C implementation from edns0.c.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Default UDP payload size for EDNS0
pub const EDNS0_DEFAULT_PAYLOAD_SIZE: u16 = 1232;

/// Maximum UDP payload size
pub const EDNS0_MAX_PAYLOAD_SIZE: u16 = 4096;

/// EDNS0 option codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edns0OptionCode {
    /// Client subnet option (RFC 7871)
    ClientSubnet,
    /// Cookie option (RFC 7873)
    Cookie,
    /// TCP keepalive (RFC 7828)
    TcpKeepalive,
    /// Padding (RFC 7830)
    Padding,
    /// Extended DNS error (RFC 8914)
    ExtendedError,
    /// Other/unknown option
    Other(u16),
}

impl Edns0OptionCode {
    /// Convert option code value to enum
    #[must_use] 
    pub fn from_code(code: u16) -> Self {
        match code {
            8 => Edns0OptionCode::ClientSubnet,
            10 => Edns0OptionCode::Cookie,
            11 => Edns0OptionCode::TcpKeepalive,
            12 => Edns0OptionCode::Padding,
            15 => Edns0OptionCode::ExtendedError,
            other => Edns0OptionCode::Other(other),
        }
    }

    /// Convert enum to option code value
    #[must_use] 
    pub fn to_code(self) -> u16 {
        match self {
            Edns0OptionCode::ClientSubnet => 8,
            Edns0OptionCode::Cookie => 10,
            Edns0OptionCode::TcpKeepalive => 11,
            Edns0OptionCode::Padding => 12,
            Edns0OptionCode::ExtendedError => 15,
            Edns0OptionCode::Other(code) => code,
        }
    }
}

/// EDNS0 client subnet information (RFC 7871)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSubnet {
    /// Client address family (1 = IPv4, 2 = IPv6)
    pub family: u16,
    
    /// Source prefix length (how many bits of address are significant)
    pub source_prefix_len: u8,
    
    /// Scope prefix length (set in response)
    pub scope_prefix_len: u8,
    
    /// Client IP address (truncated to `source_prefix_len` bits)
    pub address: IpAddr,
}

impl ClientSubnet {
    /// Create a new client subnet from IPv4 address
    #[must_use] 
    pub fn from_ipv4(addr: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            family: 1,
            source_prefix_len: prefix_len.min(32),
            scope_prefix_len: 0,
            address: IpAddr::V4(addr),
        }
    }

    /// Create a new client subnet from IPv6 address
    #[must_use] 
    pub fn from_ipv6(addr: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            family: 2,
            source_prefix_len: prefix_len.min(128),
            scope_prefix_len: 0,
            address: IpAddr::V6(addr),
        }
    }

    /// Serialize to wire format
    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Family (2 bytes)
        bytes.extend_from_slice(&self.family.to_be_bytes());
        
        // Source prefix length (1 byte)
        bytes.push(self.source_prefix_len);
        
        // Scope prefix length (1 byte)
        bytes.push(self.scope_prefix_len);
        
        // Address bytes (truncated to prefix length)
        let addr_bytes = match self.address {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        };
        
        // Calculate how many bytes we need
        let bytes_needed = self.source_prefix_len.div_ceil(8) as usize;
        bytes.extend_from_slice(&addr_bytes[..bytes_needed.min(addr_bytes.len())]);
        
        bytes
    }
}

/// EDNS0 option
#[derive(Debug, Clone)]
pub struct Edns0Option {
    /// Option code
    pub code: Edns0OptionCode,
    
    /// Option data
    pub data: Vec<u8>,
}

impl Edns0Option {
    /// Create a new EDNS0 option
    #[must_use] 
    pub fn new(code: Edns0OptionCode, data: Vec<u8>) -> Self {
        Self { code, data }
    }

    /// Create a client subnet option
    #[must_use] 
    pub fn client_subnet(subnet: &ClientSubnet) -> Self {
        Self {
            code: Edns0OptionCode::ClientSubnet,
            data: subnet.to_bytes(),
        }
    }

    /// Serialize to wire format
    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Option code (2 bytes)
        bytes.extend_from_slice(&self.code.to_code().to_be_bytes());
        
        // Option length (2 bytes)
        // EDNS0 option length is a u16 field, data should never exceed 65535 bytes
        #[allow(clippy::cast_possible_truncation)]
        let len = self.data.len() as u16;
        bytes.extend_from_slice(&len.to_be_bytes());
        
        // Option data
        bytes.extend_from_slice(&self.data);
        
        bytes
    }
}

/// EDNS0 pseudo-record (OPT RR)
#[derive(Debug, Clone)]
pub struct Edns0Record {
    /// UDP payload size
    pub payload_size: u16,
    
    /// Extended RCODE (upper 8 bits)
    pub extended_rcode: u8,
    
    /// EDNS version (should be 0)
    pub version: u8,
    
    /// DNSSEC OK flag
    pub dnssec_ok: bool,
    
    /// EDNS0 options
    pub options: Vec<Edns0Option>,
}

impl Edns0Record {
    /// Create a new EDNS0 record with default settings
    #[must_use] 
    pub fn new() -> Self {
        Self {
            payload_size: EDNS0_DEFAULT_PAYLOAD_SIZE,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            options: Vec::new(),
        }
    }

    /// Create an EDNS0 record with custom payload size
    #[must_use] 
    pub fn with_payload_size(payload_size: u16) -> Self {
        Self {
            payload_size: payload_size.min(EDNS0_MAX_PAYLOAD_SIZE),
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            options: Vec::new(),
        }
    }

    /// Enable DNSSEC OK flag
    #[must_use] 
    pub fn with_dnssec_ok(mut self) -> Self {
        self.dnssec_ok = true;
        self
    }

    /// Add an EDNS0 option
    pub fn add_option(&mut self, option: Edns0Option) {
        self.options.push(option);
    }

    /// Get the flags value for the OPT record
    #[must_use] 
    pub fn flags(&self) -> u16 {
        let mut flags = 0u16;
        if self.dnssec_ok {
            flags |= 0x8000; // DO bit
        }
        flags
    }
}

impl Default for Edns0Record {
    fn default() -> Self {
        Self::new()
    }
}

/// EDNS0 configuration
#[derive(Debug, Clone)]
pub struct Edns0Config {
    /// Enable EDNS0 support
    pub enabled: bool,
    
    /// UDP payload size to advertise
    pub payload_size: u16,
    
    /// Enable DNSSEC support
    pub dnssec_enabled: bool,
    
    /// Enable client subnet option
    pub client_subnet_enabled: bool,
}

impl Edns0Config {
    /// Create default EDNS0 configuration
    #[must_use] 
    pub fn new() -> Self {
        Self {
            enabled: true,
            payload_size: EDNS0_DEFAULT_PAYLOAD_SIZE,
            dnssec_enabled: false,
            client_subnet_enabled: false,
        }
    }

    /// Create configuration with DNSSEC enabled
    #[must_use] 
    pub fn with_dnssec() -> Self {
        Self {
            enabled: true,
            payload_size: EDNS0_DEFAULT_PAYLOAD_SIZE,
            dnssec_enabled: true,
            client_subnet_enabled: false,
        }
    }
}

impl Default for Edns0Config {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edns0_option_code() {
        assert_eq!(Edns0OptionCode::from_code(8), Edns0OptionCode::ClientSubnet);
        assert_eq!(Edns0OptionCode::ClientSubnet.to_code(), 8);
        
        let other = Edns0OptionCode::from_code(99);
        match other {
            Edns0OptionCode::Other(99) => {},
            _ => panic!("Expected Other(99)"),
        }
    }

    #[test]
    fn test_client_subnet_ipv4() {
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        let subnet = ClientSubnet::from_ipv4(addr, 24);
        
        assert_eq!(subnet.family, 1);
        assert_eq!(subnet.source_prefix_len, 24);
        assert_eq!(subnet.address, IpAddr::V4(addr));
        
        let bytes = subnet.to_bytes();
        // Family (2) + source (1) + scope (1) + 3 address bytes = 7
        assert_eq!(bytes.len(), 7);
        assert_eq!(bytes[0], 0); // Family high byte
        assert_eq!(bytes[1], 1); // Family low byte
        assert_eq!(bytes[2], 24); // Source prefix
    }

    #[test]
    fn test_client_subnet_ipv6() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let subnet = ClientSubnet::from_ipv6(addr, 48);
        
        assert_eq!(subnet.family, 2);
        assert_eq!(subnet.source_prefix_len, 48);
        assert_eq!(subnet.address, IpAddr::V6(addr));
        
        let bytes = subnet.to_bytes();
        // Family (2) + source (1) + scope (1) + 6 address bytes = 10
        assert_eq!(bytes.len(), 10);
        assert_eq!(bytes[1], 2); // Family low byte
        assert_eq!(bytes[2], 48); // Source prefix
    }

    #[test]
    fn test_edns0_option() {
        let subnet = ClientSubnet::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 24);
        let option = Edns0Option::client_subnet(&subnet);
        
        assert_eq!(option.code, Edns0OptionCode::ClientSubnet);
        
        let bytes = option.to_bytes();
        // Code (2) + length (2) + data
        assert!(bytes.len() >= 4);
        assert_eq!(bytes[0], 0); // Code high byte
        assert_eq!(bytes[1], 8); // Code low byte (8 = client subnet)
    }

    #[test]
    fn test_edns0_record_default() {
        let record = Edns0Record::new();
        
        assert_eq!(record.payload_size, EDNS0_DEFAULT_PAYLOAD_SIZE);
        assert_eq!(record.version, 0);
        assert!(!record.dnssec_ok);
        assert_eq!(record.flags(), 0);
    }

    #[test]
    fn test_edns0_record_dnssec() {
        let record = Edns0Record::new().with_dnssec_ok();
        
        assert!(record.dnssec_ok);
        assert_eq!(record.flags(), 0x8000);
    }

    #[test]
    fn test_edns0_record_custom_payload() {
        let record = Edns0Record::with_payload_size(2048);
        
        assert_eq!(record.payload_size, 2048);
    }

    #[test]
    fn test_edns0_record_max_payload() {
        let record = Edns0Record::with_payload_size(10000);
        
        // Should be clamped to max
        assert_eq!(record.payload_size, EDNS0_MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn test_edns0_config() {
        let config = Edns0Config::new();
        assert!(config.enabled);
        assert!(!config.dnssec_enabled);
        
        let dnssec_config = Edns0Config::with_dnssec();
        assert!(dnssec_config.dnssec_enabled);
    }
}
