//! Configuration file parser

use super::types::Config;

/// Parse configuration from file
pub fn parse_config_file(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    // TODO: Implement config file parsing
    Ok(Config::default())
}
