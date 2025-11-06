//! Core runtime and event loop
//!
//! This module contains the main daemon runtime, configuration,
//! signal handling, and async event loop.

pub mod daemon;
pub mod config;
pub mod signals;
pub mod event_loop;
