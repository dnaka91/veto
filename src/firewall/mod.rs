use std::{net::IpAddr, path::PathBuf};

use anyhow::Result;

pub use self::{ipset::IpSet, iptables::IpTables};

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
fn find_binary(name: &str, default: &str) -> Result<PathBuf> {
    use std::{fs, os::unix::fs::MetadataExt};

    use anyhow::ensure;

    if let Ok(path) = which::which(name) {
        return Ok(path);
    }

    let meta = fs::metadata(default)
        .map(|meta| meta.is_file() && meta.mode() & 0o111 != 0)
        .unwrap_or_default();
    ensure!(meta, "cannot find binary path of '{}'", name);

    Ok(PathBuf::from(default))
}

#[allow(clippy::unnecessary_wraps)]
#[cfg(not(target_os = "linux"))]
fn find_binary(_name: &str, default: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(default))
}
