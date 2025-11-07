//! `DHCPv6` server implementation

pub mod protocol;
pub mod options;
pub mod ia;

/// `DHCPv6` server
pub struct DhcpV6Server {}

impl Default for DhcpV6Server {
    fn default() -> Self {
        Self::new()
    }
}

impl DhcpV6Server {
    /// Create new `DHCPv6` server
    #[must_use] 
    pub fn new() -> Self {
        Self {}
    }
}
