use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{ensure, Context, Result};
use log::warn;

use super::{find_binary, Firewall, Target};
use crate::settings::IpSet as Settings;

const DEFAULT_CHAINS: &[&str] = &["INPUT", "FORWARD"];

pub struct IpSet {
    name: &'static str,
    name_v6: &'static str,
    ipset_path: PathBuf,
    iptables_path: PathBuf,
    ip6tables_path: PathBuf,
    settings: Settings,
}

impl IpSet {
    pub fn new(settings: Settings) -> Result<Self> {
        if cfg!(not(target_os = "linux")) {
            warn!("The ipset firewall is only supported on Linux systems");
            warn!("Instead you will see commands that would be run instead");
            warn!("This firewall will not do any actual work on your system");
        }

        Ok(Self {
            name: env!("CARGO_PKG_NAME"),
            name_v6: concat!(env!("CARGO_PKG_NAME"), "_v6"),
            ipset_path: find_binary("ipset", "/usr/sbin/ipset")?,
            iptables_path: find_binary("iptables", "/usr/sbin/iptables")?,
            ip6tables_path: find_binary("ip6tables", "/usr/sbin/ip6tables")?,
            settings,
        })
    }

    fn install_for(&self, name: &str, iptables: &Path, family: &str, output: &str) -> Result<()> {
        if !output.lines().any(|l| l == name) {
            let output = Command::new(&self.ipset_path)
                .args(&["create", name, "hash:ip", "family", family])
                .output()
                .context("failed running ipset")?;

            ensure!(
                output.status.success(),
                "failed creating new ipset table: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let output = Command::new(iptables)
            .arg("-S")
            .output()
            .context("failed running iptables")?;

        ensure!(
            output.status.success(),
            "failed listing iptables rules: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let output = String::from_utf8(output.stdout)?;

        for chain in DEFAULT_CHAINS {
            let rule = format!(
                "-A {} -p tcp -m multiport --dports 80,443 -m set --match-set {} src -j {}",
                chain, name, self.settings.target
            );

            if !output.lines().any(|l| l == rule) {
                let output = Command::new(iptables)
                    .args(&[
                        "-I",
                        chain,
                        "-p",
                        "tcp",
                        "-m",
                        "multiport",
                        "--dports",
                        "80,443",
                        "-m",
                        "set",
                        "--match-set",
                        name,
                        "src",
                        "-j",
                    ])
                    .args(self.settings.target.to_args())
                    .output()?;

                ensure!(
                    output.status.success(),
                    "failed adding iptables rule: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        Ok(())
    }

    fn uninstall_for(&self, name: &str, iptables: &Path) -> Result<()> {
        for chain in DEFAULT_CHAINS {
            loop {
                let output = Command::new(iptables)
                    .args(&[
                        "-D",
                        chain,
                        "-p",
                        "tcp",
                        "-m",
                        "multiport",
                        "--dports",
                        "80,443",
                        "-m",
                        "set",
                        "--match-set",
                        name,
                        "src",
                        "-j",
                    ])
                    .args(self.settings.target.to_args())
                    .output()
                    .context("failed running iptables")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if !stderr.starts_with("iptables: Bad rule ")
                        && !stderr.starts_with("ip6tables: Bad rule ")
                        && !stderr.starts_with("iptables: No chain/target/match by that name.")
                        && !stderr.starts_with("ip6tables: No chain/target/match by that name.")
                    {
                        warn!("failed deleting iptables rule: {}", stderr);
                    }
                    break;
                }
            }
        }

        let output = Command::new(&self.ipset_path)
            .args(&["destroy", name])
            .output()
            .context("failed running ipset")?;

        ensure!(
            output.status.success(),
            "failed deleting ipset table: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Ok(())
    }

    fn block_for(&self, name: &str, ip: &str) -> Result<()> {
        let output = Command::new(&self.ipset_path)
            .args(&["add", name, ip])
            .output()
            .context("failed running ipset")?;

        if !output.status.success() {
            let message = String::from_utf8_lossy(&output.stderr);
            ensure!(
                is_expected_error(&message, RunType::Add),
                "failed adding IP to ipset table: {}",
                message
            );
        }

        Ok(())
    }

    fn unblock_for(&self, name: &str, ip: &str) -> Result<()> {
        let output = Command::new(&self.ipset_path)
            .args(&["del", name, ip])
            .output()
            .context("failed running ipset")?;

        if !output.status.success() {
            let message = String::from_utf8_lossy(&output.stderr);
            ensure!(
                is_expected_error(&message, RunType::Delete),
                "failed deleting IP from ipset table: {}",
                message
            );
        }

        Ok(())
    }
}

impl Firewall for IpSet {
    fn install(&self) -> Result<()> {
        let output = Command::new(&self.ipset_path)
            .args(&["list", "-n"])
            .output()
            .context("failed running ipset")?;

        ensure!(
            output.status.success(),
            "failed listing ipset table names: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let output = String::from_utf8(output.stdout)?;

        self.install_for(self.name, &self.iptables_path, "inet", &output)?;
        self.install_for(self.name_v6, &self.ip6tables_path, "inet6", &output)?;

        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        self.uninstall_for(self.name, &self.iptables_path)?;
        self.uninstall_for(self.name_v6, &self.ip6tables_path)?;

        Ok(())
    }

    fn block<'a>(&self, target: &Target<'a>) -> Result<()> {
        match target.ip {
            IpAddr::V4(ip) => self.block_for(self.name, &ip.to_string()),
            IpAddr::V6(ip) => self.block_for(self.name_v6, &ip.to_string()),
        }
    }

    fn unblock<'a>(&self, target: &Target<'a>) -> Result<()> {
        match target.ip {
            IpAddr::V4(ip) => self.unblock_for(self.name, &ip.to_string()),
            IpAddr::V6(ip) => self.unblock_for(self.name_v6, &ip.to_string()),
        }
    }
}

#[derive(Copy, Clone)]
enum RunType {
    Add,
    Delete,
}

fn is_expected_error(message: &str, ty: RunType) -> bool {
    let mut parts = message.splitn(2, ": ");

    if let (Some(prefix), Some(msg)) = (parts.next(), parts.next()) {
        return prefix.starts_with("ipset v")
            && msg.trim()
                == match ty {
                    RunType::Add => "Element cannot be added to the set: it's already added",
                    RunType::Delete => "Element cannot be deleted from the set: it's not added",
                };
    }

    false
}
