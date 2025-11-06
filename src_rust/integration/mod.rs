//! External integrations
#[cfg(feature = "dbus")]
pub mod dbus;

#[cfg(all(feature = "inotify", target_os = "linux"))]
pub mod inotify;
