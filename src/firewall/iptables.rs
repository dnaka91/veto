use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{ensure, Result};
use itertools::Itertools;
use log::debug;

use super::{find_binary, Firewall, Target};

pub struct IpTables {
    name: &'static str,
    iptables_path: PathBuf,
    ip6tables_path: PathBuf,
}

impl IpTables {
    #[allow(dead_code)]
    pub fn new() -> Result<Self> {
        Ok(Self {
            name: env!("CARGO_PKG_NAME"),
            iptables_path: find_binary("iptables")?,
            ip6tables_path: find_binary("ip6tables")?,
        })
    }

    fn block_args<'a>(cmd: &mut Command, target: &Target<'a>) {
        cmd.args(&["-s", &target.ip.to_string(), "-p", "tcp"]);

        if !target.ports.is_empty() {
            cmd.args(&[
                "-m",
                "multiport",
                "--dports",
                &target.ports.iter().join(","),
            ]);
        }

        cmd.args(&["-j", "REJECT", "--reject-with", "tcp-reset"]);
    }

    fn select_cmd(&self, ip: IpAddr) -> &Path {
        match ip {
            IpAddr::V4(_) => &self.iptables_path,
            IpAddr::V6(_) => &self.ip6tables_path,
        }
    }
}

impl Firewall for IpTables {
    fn install(&self) -> Result<()> {
        let cmds = &[
            vec!["-N", self.name],
            vec!["-A", self.name, "-j", "ACCEPT"],
            vec![
                "-I", "INPUT", "-m", "state", "--state", "NEW", "-p", "tcp", "-j", self.name,
            ],
        ];

        for args in cmds {
            let mut cmd = Command::new(&self.iptables_path);
            cmd.args(args);

            if cfg!(debug_assertions) {
                debug!("install: {:?}", cmd);
            } else {
                ensure!(
                    cmd.status()?.success(),
                    "Failed running iptables to install rule chain"
                );
            }
        }

        for args in cmds {
            let mut cmd = Command::new(&self.ip6tables_path);
            cmd.args(args);

            if cfg!(debug_assertions) {
                debug!("install: {:?}", cmd);
            } else {
                ensure!(
                    cmd.status()?.success(),
                    "Failed running ip6tables to install rule chain"
                );
            }
        }

        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        let cmds = &[
            vec![
                "-D", "INPUT", "-m", "state", "--state", "NEW", "-p", "tcp", "-j", self.name,
            ],
            vec!["-F", self.name],
            vec!["-X", self.name],
        ];

        for args in cmds {
            let mut cmd = Command::new(&self.iptables_path);
            cmd.args(args);

            if cfg!(debug_assertions) {
                debug!("uninstall: {:?}", cmd);
            } else {
                ensure!(
                    cmd.status()?.success(),
                    "Failed running iptables to uninstall rule chain"
                );
            }
        }

        for args in cmds {
            let mut cmd = Command::new(&self.ip6tables_path);
            cmd.args(args);

            if cfg!(debug_assertions) {
                debug!("uninstall: {:?}", cmd);
            } else {
                ensure!(
                    cmd.status()?.success(),
                    "Failed running ip6tables to uninstall rule chain"
                );
            }
        }

        Ok(())
    }

    fn block<'a>(&self, target: &Target<'a>) -> Result<()> {
        let mut cmd = Command::new(self.select_cmd(target.ip));

        cmd.args(&["-I", self.name]);

        Self::block_args(&mut cmd, target);

        if cfg!(debug_assertions) {
            debug!("block: {:?}", cmd);
        } else {
            ensure!(
                cmd.status()?.success(),
                "Failed running iptables to block target"
            );
        }

        Ok(())
    }

    fn unblock<'a>(&self, target: &Target<'a>) -> Result<()> {
        let mut cmd = Command::new(self.select_cmd(target.ip));

        cmd.args(&["-D", self.name]);

        Self::block_args(&mut cmd, target);

        if cfg!(debug_assertions) {
            debug!("block: {:?}", cmd);
        } else {
            ensure!(
                cmd.status()?.success(),
                "Failed running iptables to unblock target"
            );
        }

        Ok(())
    }
}
