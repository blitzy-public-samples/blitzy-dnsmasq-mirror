//! Monitoring and metrics
//!
//! This module provides Prometheus metrics export functionality for dnsmasq.

pub mod types;

#[cfg(feature = "prometheus-metrics")]
pub mod metrics;

#[cfg(feature = "prometheus-metrics")]
pub use metrics::MetricsCollector;

#[cfg(not(feature = "prometheus-metrics"))]
/// Stub implementation when prometheus-metrics feature is disabled
pub struct MetricsCollector;
