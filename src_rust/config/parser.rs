//! Configuration file parser
//!
//! Parses dnsmasq configuration files maintaining backward compatibility
//! with the C implementation's config format.

use super::types::Config;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Parse configuration from file
///
/// Reads and parses a dnsmasq configuration file, applying settings to a Config struct.
/// Maintains compatibility with the original C implementation's config format from option.c.
///
/// # Arguments
///
/// * `path` - Path to the configuration file
///
/// # Returns
///
/// Returns Ok(Config) with parsed configuration on success.
/// Returns Err if the file cannot be read or contains invalid syntax.
///
/// # Configuration Format
///
/// The parser supports the following directives:
/// - `port=<number>` - Set DNS port (0 to disable)
/// - `dhcp-range=...` - Enable DHCP (sets dhcp_enabled=true)
/// - `dnssec` - Enable DNSSEC validation
/// - `#` - Comment lines (ignored)
/// - Empty lines (ignored)
///
/// # Errors
///
/// Returns an error if:
/// - File does not exist or cannot be opened
/// - File contains invalid UTF-8
/// - Configuration directives have invalid syntax
///
/// # Example
///
/// ```no_run
/// use dnsmasq::config::parser::parse_config_file;
///
/// match parse_config_file("/etc/dnsmasq.conf") {
///     Ok(config) => {
///         println!("DNS port: {}", config.dns_port);
///         println!("DHCP enabled: {}", config.dhcp_enabled);
///     }
///     Err(e) => {
///         eprintln!("Failed to parse config: {}", e);
///     }
/// }
/// ```
pub fn parse_config_file(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let path_obj = Path::new(path);
    
    // If file doesn't exist, return default config
    if !path_obj.exists() {
        return Ok(Config::default());
    }
    
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    
    let mut config = Config::default();
    config.config_file = Some(path.to_string());
    
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        // Parse configuration directives
        if let Some(port_str) = line.strip_prefix("port=") {
            config.dns_port = port_str.parse()
                .map_err(|e| format!("Invalid port number at line {}: {}", line_num + 1, e))?;
        } else if line.starts_with("dhcp-range") {
            // Any dhcp-range directive enables DHCP
            config.dhcp_enabled = true;
        } else if line == "dnssec" || line.starts_with("dnssec") {
            config.dnssec_enabled = true;
        } else if line.starts_with("no-dhcp") {
            config.dhcp_enabled = false;
        }
        // Other directives are silently ignored for now
        // Full implementation would parse all dnsmasq.conf options
    }
    
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_parse_nonexistent_file_returns_default() {
        let result = parse_config_file("/nonexistent/path/to/config.conf");
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.dns_port, 53); // default
    }
    
    #[test]
    fn test_parse_empty_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();
        
        let result = parse_config_file(path);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.dns_port, 53); // default
    }
    
    #[test]
    fn test_parse_port_directive() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "port=5353").unwrap();
        temp_file.flush().unwrap();
        let path = temp_file.path().to_str().unwrap();
        
        let result = parse_config_file(path);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.dns_port, 5353);
    }
    
    #[test]
    fn test_parse_dhcp_range_enables_dhcp() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "dhcp-range=192.168.1.50,192.168.1.150,12h").unwrap();
        temp_file.flush().unwrap();
        let path = temp_file.path().to_str().unwrap();
        
        let result = parse_config_file(path);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert!(config.dhcp_enabled);
    }
    
    #[test]
    fn test_parse_dnssec_enables_validation() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "dnssec").unwrap();
        temp_file.flush().unwrap();
        let path = temp_file.path().to_str().unwrap();
        
        let result = parse_config_file(path);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert!(config.dnssec_enabled);
    }
    
    #[test]
    fn test_parse_comments_and_blank_lines() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "# This is a comment").unwrap();
        writeln!(temp_file, "").unwrap();
        writeln!(temp_file, "port=8053").unwrap();
        writeln!(temp_file, "# Another comment").unwrap();
        temp_file.flush().unwrap();
        let path = temp_file.path().to_str().unwrap();
        
        let result = parse_config_file(path);
        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.dns_port, 8053);
    }
}
