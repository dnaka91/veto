use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Result;

pub use ipset::IpSet;
pub use iptables::IpTables;

mod ipset;
mod iptables;

/// Information to block a specific IP on the firewall.
pub struct Target<'a> {
    /// IP address to block requests from.
    pub ip: IpAddr,
    /// Optional list of ports that the access is blocked for. If the list is empty, then all ports
    /// are blocked.
    pub ports: &'a [u16],
}

/// A firewall can block and unblock requests from certain IPs.
pub trait Firewall {
    /// Setup the firewall for usage. This usually installs filters needed for easy IP blocking.
    fn install(&self) -> Result<()>;
    /// Remove any previously added changes from [`Self::install`] and unblock all IPs.
    fn uninstall(&self) -> Result<()>;
    /// Add a new entry to the firewall, effectively blocking requests from the given IP.
    fn block<'a>(&self, target: &Target<'a>) -> Result<()>;
    /// Remove an entry from the firewall.
    fn unblock<'a>(&self, target: &Target<'a>) -> Result<()>;
}

#[cfg(target_os = "linux")]
fn find_binary(name: &str) -> Result<PathBuf> {
    which::which(name).map_err(Into::into)
}

#[cfg(not(target_os = "linux"))]
fn find_binary(name: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(name))
}
