use std::fmt;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Duration;
use ipnetwork::IpNetwork;
use log::info;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};

use crate::{HashMap, IndexMap, IndexSet};

/// Structure holding all application settings.
#[derive(Debug, Deserialize)]
pub struct Settings {
    /// List of IP network masks to ignore.
    #[serde(default)]
    pub whitelist: Vec<IpNetwork>,
    /// List of rules to apply.
    pub rules: HashMap<String, Rule>,
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
