use std::{
    fmt::{self, Display},
    fs,
    path::PathBuf,
};

use anyhow::{Context, Result};
use chrono::Duration;
use ipnetwork::IpNetwork;
use log::info;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer,
};

use crate::{HashMap, IndexMap, IndexSet};

/// Structure holding all application settings.
#[derive(Debug, Deserialize)]
pub struct Settings {
    /// List of IP network masks to ignore.
    #[serde(default)]
    pub whitelist: Vec<IpNetwork>,
    /// Settings for the ipset firewall.
    #[serde(default)]
    pub ipset: IpSet,
    /// List of rules to apply.
    pub rules: HashMap<String, Rule>,
}

/// Structure holding settings specific to the ipset firewall.
#[derive(Debug, Default, Deserialize)]
pub struct IpSet {
    /// Target to send matched IPs to in **iptables**.
    pub target: IptablesTarget,
}

/// Different targets that a matched IP can be send to in iptables.
#[derive(Copy, Clone, Debug, Deserialize)]
pub enum IptablesTarget {
    /// Drop the packets, making the server look as it would not exist.
    Drop,
    /// Explicitly reject the packets, returning an error to the client.
    Reject,
    /// Lock the client into a tarpit, forcing automated bots into a long running connection that
    /// wastes their time but doesn't take any additional resources on the system.
    ///
    /// **Note**: For this target to work, the iptables addons need to be installed on the system
    /// (`xtables-addons-dkms` package on Debian).
    Tarpit,
}

impl IptablesTarget {
    #[must_use]
    pub const fn to_args(self) -> &'static [&'static str] {
        match self {
            Self::Drop => &["DROP"],
            Self::Reject => &["REJECT"],
            Self::Tarpit => &["TARPIT", "--tarpit"],
        }
    }
}

impl Default for IptablesTarget {
    fn default() -> Self {
        Self::Drop
    }
}

impl Display for IptablesTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Drop => "DROP",
            Self::Reject => "REJECT",
            Self::Tarpit => "TARPIT --tarpit",
        })
    }
}

/// A rule describes the file to track with filters and blacklists to detect malicious accesses.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    /// The file to track for changes and scan for access logs.
    pub file: PathBuf,
    /// List of regex filters to extract information.
    pub filters: Vec<String>,
    /// Ports to block in case a malicious access was found.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Timeout duration on the blocklist.
    #[serde(deserialize_with = "human_duration")]
    pub timeout: Duration,
    /// Blacklisted words that trigger a block.
    ///
    /// The key is the name of a regex catch group within the `filters` property thus the blacklist
    /// is compared against the extracted content of a catch group.
    ///
    /// If no blacklists are defined, then the filter match is enough to block a IP.
    #[serde(default)]
    pub blacklists: IndexMap<String, IndexSet<String>>,
}

/// Load the application settings from the given path or the OS-specific default location otherwise.
pub fn load(path: Option<PathBuf>) -> Result<Settings> {
    let path = path.unwrap_or_else(|| PathBuf::from("/etc/veto/config.toml"));

    info!("Attempting to load settings from {:?}", path);

    let content = fs::read(path).context("Failed reading settings file")?;

    toml::from_slice(&content).map_err(Into::into)
}

/// Parse a human representation like `2h 15m` into a [`Duration`].
///
/// It can be used with serde by specifying `#[serde(deserialize_with = "human_duration")]` on a
/// property within a struct.
fn human_duration<'de, D>(deserializer: D) -> std::result::Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    struct DurationVisitor;

    impl<'de> Visitor<'de> for DurationVisitor {
        type Value = Duration;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a duration")
        }

        fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            humantime::parse_duration(v)
                .ok()
                .and_then(|d| Duration::from_std(d).ok())
                .ok_or_else(|| E::invalid_value(de::Unexpected::Str(v), &self))
        }
    }

    deserializer.deserialize_str(DurationVisitor)
}
