use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{ensure, Context, Result};
use log::warn;

use super::{find_binary, Firewall, Target};

const DEFAULT_CHAINS: &[&str] = &["INPUT", "FORWARD"];

pub struct IpSet {
    name: &'static str,
    ipset_path: PathBuf,
    iptables_path: PathBuf,
}

impl IpSet {
    pub fn new() -> Result<Self> {
        if cfg!(not(target_os = "linux")) {
            warn!("The ipset firewall is only supported on Linux systems");
            warn!("Instead you will see commands that would be run instead");
            warn!("This firewall will not do any actual work on your system");
        }

        Ok(Self {
            name: env!("CARGO_PKG_NAME"),
            ipset_path: find_binary("ipset")?,
            iptables_path: find_binary("iptables")?,
        })
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

        if !output.lines().any(|l| l == self.name) {
            let output = Command::new(&self.ipset_path)
                .args(&["create", self.name, "hash:ip"])
                .output()
                .context("failed running ipset")?;

            ensure!(
                output.status.success(),
                "failed creating new ipset table: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let output = Command::new(&self.iptables_path)
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
                "-A {} -p tcp -m multiport --dports 80,443 -m set --match-set {} src -j DROP",
                chain, &self.name
            );

            if !output.lines().any(|l| l == rule) {
                let output = Command::new(&self.iptables_path)
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
                        self.name,
                        "src",
                        "-j",
                        "DROP",
                    ])
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

    fn uninstall(&self) -> Result<()> {
        for chain in DEFAULT_CHAINS {
            loop {
                let output = Command::new(&self.iptables_path)
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
                        self.name,
                        "src",
                        "-j",
                        "DROP",
                    ])
                    .output()
                    .context("failed running iptables")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if !stderr.starts_with("iptables: Bad rule ") {
                        warn!("failed deleting iptables rule: {}", stderr);
                    }
                    break;
                }
            }
        }

        let output = Command::new(&self.ipset_path)
            .args(&["destroy", self.name])
            .output()
            .context("failed running ipset")?;

        ensure!(
            output.status.success(),
            "failed deleting ipset table: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        Ok(())
    }

    fn block<'a>(&self, target: &Target<'a>) -> Result<()> {
        if let IpAddr::V4(ip) = target.ip {
            let output = Command::new(&self.ipset_path)
                .args(&["add", self.name, &ip.to_string()])
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
        } else {
            warn!("ipv6 addresses not supported yet");
        }

        Ok(())
    }

    fn unblock<'a>(&self, target: &Target<'a>) -> Result<()> {
        if let IpAddr::V4(ip) = target.ip {
            let output = Command::new(&self.ipset_path)
                .args(&["del", self.name, &ip.to_string()])
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
        } else {
            warn!("ipv6 addresses not supported yet");
        }

        Ok(())
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
