// Build script for dnsmasq-rs
// This script handles platform-specific build configuration and linking

fn main() {
    // Link to libnetfilter_conntrack when conntrack feature is enabled
    #[cfg(feature = "conntrack")]
    {
        println!("cargo:rustc-link-lib=netfilter_conntrack");

        // Try using pkg-config to find the library
        if let Err(e) = pkg_config::probe_library("libnetfilter_conntrack") {
            eprintln!(
                "Warning: pkg-config for libnetfilter_conntrack failed: {}",
                e
            );
            eprintln!("Falling back to default library search path");
        }
    }

    // Rerun build script if build.rs changes
    println!("cargo:rerun-if-changed=build.rs");
}
