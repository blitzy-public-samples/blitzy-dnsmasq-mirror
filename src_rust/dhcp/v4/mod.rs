//! `DHCPv4` server implementation

pub mod protocol;
pub mod options;
pub mod ping;
pub mod handler;
pub mod server;

/// `DHCPv4` server
pub struct DhcpV4Server {}

impl Default for DhcpV4Server {
    fn default() -> Self {
        Self::new()
    }
}

impl DhcpV4Server {
    /// Create new `DHCPv4` server
    #[must_use] 
    pub fn new() -> Self {
        Self {}
    }
}
