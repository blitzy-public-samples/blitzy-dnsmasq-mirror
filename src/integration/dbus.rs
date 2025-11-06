// dnsmasq-rs: Memory-safe Rust implementation of dnsmasq
// Copyright (c) 2000-2022 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.

//! D-Bus integration for NetworkManager and system bus
//!
//! This module provides D-Bus interfaces for desktop Linux integration, replacing
//! the C implementation in `src/dbus.c` with async Rust using the zbus crate.
//!
//! # Purpose
//!
//! Provides D-Bus signals and methods for:
//! - DHCP lease change notifications
//! - DNS cache clear requests
//! - Server configuration updates
//! - Service status queries
//!
//! # D-Bus Interface
//!
//! Service: uk.org.thekelleys.dnsmasq
//! Path: /uk/org/thekelleys/dnsmasq
//! Interface: uk.org.thekelleys.dnsmasq
//!
//! Signals:
//! - DhcpLeaseAdded(mac: s, ip: s, hostname: s)
//! - DhcpLeaseDeleted(mac: s, ip: s, hostname: s)
//! - DhcpLeaseUpdated(mac: s, ip: s, hostname: s)
//!
//! Methods:
//! - GetVersion() -> s
//! - ClearCache() -> ()
//! - GetLeaseCount() -> u32

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use zbus::{Connection, Result as ZbusResult, SignalContext, interface};

/// D-Bus service name
const DBUS_SERVICE_NAME: &str = "uk.org.thekelleys.dnsmasq";

/// D-Bus object path
const DBUS_OBJECT_PATH: &str = "/uk/org/thekelleys/dnsmasq";

/// D-Bus interface name
const DBUS_INTERFACE_NAME: &str = "uk.org.thekelleys.dnsmasq";

/// D-Bus integration errors
#[derive(Debug, Error)]
pub enum DbusError {
    /// Failed to connect to D-Bus
    #[error("Failed to connect to D-Bus: {0}")]
    ConnectionFailed(String),

    /// Failed to register service name
    #[error("Failed to register service name: {0}")]
    NameRegistrationFailed(String),

    /// Failed to register object
    #[error("Failed to register object: {0}")]
    ObjectRegistrationFailed(String),

    /// Failed to emit signal
    #[error("Failed to emit D-Bus signal: {0}")]
    SignalEmitFailed(String),

    /// D-Bus method call failed
    #[error("D-Bus method call failed: {0}")]
    MethodCallFailed(String),

    /// Zbus error
    #[error("Zbus error: {0}")]
    Zbus(#[from] zbus::Error),

    /// Zbus fdo error
    #[error("Zbus fdo error: {0}")]
    ZbusFdo(#[from] zbus::fdo::Error),
}

/// DHCP lease information for D-Bus signals
#[derive(Debug, Clone)]
pub struct LeaseInfo {
    /// MAC address
    pub mac_address: String,
    
    /// IP address
    pub ip_address: IpAddr,
    
    /// Hostname (if known)
    pub hostname: Option<String>,
    
    /// Lease expiry time (Unix timestamp)
    pub expiry_time: Option<u64>,
}

/// DNS server specification
#[derive(Debug, Clone)]
pub struct ServerSpec {
    /// Server address
    pub address: IpAddr,
    
    /// Server port
    pub port: u16,
    
    /// Domain (if server-specific)
    pub domain: Option<String>,
}

/// D-Bus interface implementation
///
/// This struct implements the dnsmasq D-Bus interface, providing methods and signals
/// for system integration. It maintains internal state for lease tracking and
/// server configuration.
#[derive(Clone)]
struct DnsmasqDbusInterface {
    /// DHCP lease count
    lease_count: Arc<RwLock<u32>>,
    
    /// DNS cache size
    cache_size: Arc<RwLock<u32>>,
    
    /// Upstream DNS servers
    servers: Arc<RwLock<Vec<ServerSpec>>>,
}

#[interface(name = "uk.org.thekelleys.dnsmasq")]
impl DnsmasqDbusInterface {
    /// Get dnsmasq version
    async fn get_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Clear DNS cache
    async fn clear_cache(&self) {
        info!("D-Bus method called: ClearCache");
        
        // In full implementation, this would call into dns::cache module
        // For now, just reset the cache size counter
        let mut cache_size = self.cache_size.write().await;
        *cache_size = 0;
    }

    /// Get current DHCP lease count
    async fn get_lease_count(&self) -> u32 {
        let lease_count = self.lease_count.read().await;
        *lease_count
    }

    /// Get DNS cache size
    async fn get_cache_size(&self) -> u32 {
        let cache_size = self.cache_size.read().await;
        *cache_size
    }

    /// Get list of upstream DNS servers
    async fn get_servers(&self) -> Vec<String> {
        let servers = self.servers.read().await;
        servers
            .iter()
            .map(|s| {
                if let Some(ref domain) = s.domain {
                    format!("{}:{} ({})", s.address, s.port, domain)
                } else {
                    format!("{}:{}", s.address, s.port)
                }
            })
            .collect()
    }

    /// Set upstream DNS servers
    async fn set_servers(&self, servers: Vec<String>) {
        info!("D-Bus method called: SetServers({} servers)", servers.len());
        
        // Parse server specifications
        let mut parsed_servers = Vec::new();
        for server_str in servers {
            // Simple parsing: "ip:port" or "ip:port (domain)"
            // Full implementation would have robust parsing
            if let Some((addr_port, domain)) = server_str.split_once(" (") {
                if let Some((addr_str, port_str)) = addr_port.split_once(':') {
                    if let (Ok(addr), Ok(port)) = (addr_str.parse(), port_str.parse()) {
                        let domain = domain.trim_end_matches(')').to_string();
                        parsed_servers.push(ServerSpec {
                            address: addr,
                            port,
                            domain: Some(domain),
                        });
                    }
                }
            } else if let Some((addr_str, port_str)) = server_str.split_once(':') {
                if let (Ok(addr), Ok(port)) = (addr_str.parse(), port_str.parse()) {
                    parsed_servers.push(ServerSpec {
                        address: addr,
                        port,
                        domain: None,
                    });
                }
            }
        }
        
        let mut servers_lock = self.servers.write().await;
        *servers_lock = parsed_servers;
    }

    /// Signal: DHCP lease added
    #[zbus(signal)]
    async fn dhcp_lease_added(
        signal_ctxt: &SignalContext<'_>,
        mac: &str,
        ip: &str,
        hostname: &str,
    ) -> zbus::Result<()>;

    /// Signal: DHCP lease deleted
    #[zbus(signal)]
    async fn dhcp_lease_deleted(
        signal_ctxt: &SignalContext<'_>,
        mac: &str,
        ip: &str,
        hostname: &str,
    ) -> zbus::Result<()>;

    /// Signal: DHCP lease updated
    #[zbus(signal)]
    async fn dhcp_lease_updated(
        signal_ctxt: &SignalContext<'_>,
        mac: &str,
        ip: &str,
        hostname: &str,
    ) -> zbus::Result<()>;
}

/// D-Bus interface handle
///
/// Provides high-level interface for emitting signals and calling methods.
pub struct DbusInterface {
    /// D-Bus connection
    connection: Connection,
    
    /// Internal interface implementation (shared state)
    interface_impl: Arc<DnsmasqDbusInterface>,
}

impl DbusInterface {
    /// Connect to system D-Bus and register interface
    ///
    /// # Errors
    ///
    /// Returns `DbusError::ConnectionFailed` if connection fails.
    /// Returns `DbusError::NameRegistrationFailed` if service name registration fails.
    /// Returns `DbusError::ObjectRegistrationFailed` if object registration fails.
    pub async fn connect() -> Result<Self, DbusError> {
        info!("Connecting to D-Bus system bus");

        // Connect to system bus
        let connection = Connection::system()
            .await
            .map_err(|e| DbusError::ConnectionFailed(e.to_string()))?;

        // Request service name
        connection
            .request_name(DBUS_SERVICE_NAME)
            .await
            .map_err(|e| DbusError::NameRegistrationFailed(e.to_string()))?;

        info!("D-Bus service name registered: {}", DBUS_SERVICE_NAME);

        // Create interface implementation
        let interface_impl = DnsmasqDbusInterface {
            lease_count: Arc::new(RwLock::new(0)),
            cache_size: Arc::new(RwLock::new(0)),
            servers: Arc::new(RwLock::new(Vec::new())),
        };

        // Get object server and register interface
        connection
            .object_server()
            .at(DBUS_OBJECT_PATH, interface_impl.clone())
            .await
            .map_err(|e| DbusError::ObjectRegistrationFailed(e.to_string()))?;

        info!("D-Bus object registered at path: {}", DBUS_OBJECT_PATH);

        Ok(Self {
            connection,
            interface_impl: Arc::new(interface_impl),
        })
    }

    /// Emit DHCP lease added signal
    pub async fn emit_lease_added(&self, lease: &LeaseInfo) -> Result<(), DbusError> {
        debug!(
            "Emitting DhcpLeaseAdded signal: {} -> {}",
            lease.mac_address, lease.ip_address
        );

        let mac = lease.mac_address.as_str();
        let ip = lease.ip_address.to_string();
        let hostname = lease.hostname.as_deref().unwrap_or("");

        // Get interface reference for signal emission
        let iface_ref = self
            .connection
            .object_server()
            .interface::<_, DnsmasqDbusInterface>(DBUS_OBJECT_PATH)
            .await
            .map_err(|e| DbusError::SignalEmitFailed(e.to_string()))?;

        // Emit signal
        DnsmasqDbusInterface::dhcp_lease_added(iface_ref.signal_context(), mac, &ip, hostname)
            .await
            .map_err(|e| DbusError::SignalEmitFailed(e.to_string()))?;

        // Update lease count
        let mut lease_count = self.interface_impl.lease_count.write().await;
        *lease_count += 1;

        Ok(())
    }

    /// Emit DHCP lease deleted signal
    pub async fn emit_lease_deleted(&self, lease: &LeaseInfo) -> Result<(), DbusError> {
        debug!(
            "Emitting DhcpLeaseDeleted signal: {} -> {}",
            lease.mac_address, lease.ip_address
        );

        let mac = lease.mac_address.as_str();
        let ip = lease.ip_address.to_string();
        let hostname = lease.hostname.as_deref().unwrap_or("");

        // Get interface reference for signal emission
        let iface_ref = self
            .connection
            .object_server()
            .interface::<_, DnsmasqDbusInterface>(DBUS_OBJECT_PATH)
            .await
            .map_err(|e| DbusError::SignalEmitFailed(e.to_string()))?;

        // Emit signal
        DnsmasqDbusInterface::dhcp_lease_deleted(iface_ref.signal_context(), mac, &ip, hostname)
            .await
            .map_err(|e| DbusError::SignalEmitFailed(e.to_string()))?;

        // Update lease count
        let mut lease_count = self.interface_impl.lease_count.write().await;
        if *lease_count > 0 {
            *lease_count -= 1;
        }

        Ok(())
    }

    /// Emit DHCP lease updated signal
    pub async fn emit_lease_updated(&self, lease: &LeaseInfo) -> Result<(), DbusError> {
        debug!(
            "Emitting DhcpLeaseUpdated signal: {} -> {}",
            lease.mac_address, lease.ip_address
        );

        let mac = lease.mac_address.as_str();
        let ip = lease.ip_address.to_string();
        let hostname = lease.hostname.as_deref().unwrap_or("");

        // Get interface reference for signal emission
        let iface_ref = self
            .connection
            .object_server()
            .interface::<_, DnsmasqDbusInterface>(DBUS_OBJECT_PATH)
            .await
            .map_err(|e| DbusError::SignalEmitFailed(e.to_string()))?;

        // Emit signal
        DnsmasqDbusInterface::dhcp_lease_updated(iface_ref.signal_context(), mac, &ip, hostname)
            .await
            .map_err(|e| DbusError::SignalEmitFailed(e.to_string()))?;

        Ok(())
    }

    /// Update DNS cache size
    pub async fn set_cache_size(&self, size: u32) {
        let mut cache_size = self.interface_impl.cache_size.write().await;
        *cache_size = size;
    }

    /// Update upstream DNS servers
    pub async fn set_servers(&self, servers: Vec<ServerSpec>) {
        let mut servers_lock = self.interface_impl.servers.write().await;
        *servers_lock = servers;
    }

    /// Get D-Bus connection (for custom method calls if needed)
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_info_creation() {
        let lease = LeaseInfo {
            mac_address: "00:11:22:33:44:55".to_string(),
            ip_address: "192.168.1.100".parse().unwrap(),
            hostname: Some("test-host".to_string()),
            expiry_time: Some(3600),
        };

        assert_eq!(lease.mac_address, "00:11:22:33:44:55");
        assert_eq!(lease.ip_address.to_string(), "192.168.1.100");
        assert_eq!(lease.hostname, Some("test-host".to_string()));
        assert_eq!(lease.expiry_time, Some(3600));
    }

    #[test]
    fn test_server_spec_creation() {
        let server = ServerSpec {
            address: "8.8.8.8".parse().unwrap(),
            port: 53,
            domain: Some("google.com".to_string()),
        };

        assert_eq!(server.address.to_string(), "8.8.8.8");
        assert_eq!(server.port, 53);
        assert_eq!(server.domain, Some("google.com".to_string()));
    }

    #[test]
    fn test_constants() {
        assert_eq!(DBUS_SERVICE_NAME, "uk.org.thekelleys.dnsmasq");
        assert_eq!(DBUS_OBJECT_PATH, "/uk/org/thekelleys/dnsmasq");
        assert_eq!(DBUS_INTERFACE_NAME, "uk.org.thekelleys.dnsmasq");
    }
}
