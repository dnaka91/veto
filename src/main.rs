#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, clippy::all, clippy::pedantic)]
#![warn(clippy::nursery)]

use std::{env, path::PathBuf, time::Duration as StdDuration};

use anyhow::{Context, Result};
use chrono::{prelude::*, Duration};
use clap::{ArgAction, Parser};
use crossbeam_channel::{select, Receiver};
use log::{info, warn};
use veto::{
    firewall::{self, Firewall},
    handler,
    handler::Handler,
    matcher::Matcher,
    notifier, settings, storage,
    storage::TargetRepository,
};

/// A lightweight, log file based IP blocker with focus on simplicity and speed.
#[derive(Parser)]
#[command(about, author, version)]
struct Opts {
    /// Level of verbosity.
    ///
    /// Pass the flag once (-v) for slight verbosity with informative logs. Pass it twice (-vv) to
    /// include debug information as well. Pass it trice (-vvv) or more to be super verbose and log
    /// as much as possible.
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
    /// Alternative configuration location.
    #[arg(long, env = "VETO_CONFIG")]
    config: Option<PathBuf>,
    /// Alternative storage location.
    #[arg(long, env = "VETO_STORAGE")]
    storage: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Option<Command>,
}

#[derive(Parser)]
enum Command {
    /// Remove any leftover firewall rules.
    Uninstall,
    /// Match against a single log line and show statistics.
    Analyze {
        /// One of the configured rules to load.
        #[arg(long, short)]
        rule: String,
        /// The log line to match against.
        line: String,
    },
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let opts: Opts = Opts::parse();

    env::set_var(
        "RUST_LOG",
        match opts.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        },
    );
    pretty_env_logger::init();

    if let Some(cmd) = opts.cmd {
        match cmd {
            Command::Uninstall => uninstall(opts.config)?,
            Command::Analyze { rule, line } => analyze(opts.config, &rule, &line)?,
        }
        return Ok(());
    }

    let settings = settings::load(opts.config)?;

    let shutdown = create_shutdown()?;

    let firewall = firewall::IpSet::new(settings.ipset)?;

    let storage = storage::new_storage(opts.storage);

    let mut files = handler::prepare_rules(settings.rules)?;

    let last_unblock = Utc::now() + Duration::minutes(1);

    firewall.install()?;

    storage.iter_active(|addr, file| {
        if let Some((entry, _)) = files.get(file) {
            let target = &firewall::Target {
                ip: addr,
                ports: &entry.rule.ports,
            };
            if let Err(e) = firewall.block(target) {
                warn!("failed blocking {}: {:?}", addr, e);
            }
        }

        Ok(())
    })?;

    let mut handler = Handler {
        whitelist: settings.whitelist,
        storage,
        firewall,
        last_unblock,
    };

    for (entry, state) in files.values_mut() {
        handler.handle_modified(entry, state)?;
    }

    let events = notifier::start(files.keys())?;
    let unblock = crossbeam_channel::tick(StdDuration::from_secs(60));

    #[allow(clippy::useless_transmute)]
    loop {
        select! {
            recv(shutdown) -> _ => {
                info!("shutting down");
                break;
            }
            recv(events.rx) -> event => handler.handle_event(&mut files, event.unwrap())?,
            recv(unblock) -> _ => handler.handle_unblock(&files)?,
        }
    }

    handler.firewall.uninstall()?;

    Ok(())
}

fn create_shutdown() -> Result<Receiver<()>> {
    let (tx, rx) = crossbeam_channel::bounded(0);

    ctrlc::set_handler(move || {
        if let Err(e) = tx.send(()) {
            warn!("failed sending shutdown signal: {:?}", e);
        }
    })?;

    Ok(rx)
}

fn uninstall(config: Option<PathBuf>) -> Result<()> {
    let settings = settings::load(config)?;
    firewall::IpSet::new(settings.ipset)?.uninstall()
}

fn analyze(config: Option<PathBuf>, rule: &str, line: &str) -> Result<()> {
    let mut settings = settings::load(config)?;
    let entry = handler::prepare_rule(
        rule.to_owned(),
        settings.rules.remove(rule).context("rule doesn't exist")?,
    )?;
    let matcher = Matcher::new();

    let analysis = matcher.find_analyze(&entry, line);

    for (filter, matched) in analysis.matches {
        println!("Filter: {}", filter);
        if let Some(matched) = matched {
            println!("  Captures:");
            let name_len = matched
                .captures
                .iter()
                .map(|c| c.0.len())
                .max()
                .unwrap_or_default();

            for (name, value) in matched.captures {
                println!("    {:2$}: {}", name, value.unwrap_or_default(), name_len);
            }

            println!(
                "  Time: {}",
                match matched.time {
                    Some((time, outdated)) =>
                        format!("{} {}", time, if outdated { "(outdated)" } else { "" }),
                    None => "no timetamp found".to_owned(),
                }
            );

            println!(
                "  Host: {}",
                match matched.host {
                    Some(host) => match host {
                        std::net::IpAddr::V4(addr) => format!("IPv4 {}", addr),
                        std::net::IpAddr::V6(addr) => format!("IPv6 {}", addr),
                    },
                    None => "no host found".to_owned(),
                }
            );

            let name_len = matched
                .blacklists
                .iter()
                .map(|b| b.0.len())
                .max()
                .unwrap_or_default();

            println!("  Blacklists:");
            for (name, pattern) in matched.blacklists {
                println!("    {:2$}: {}", name, pattern, name_len);
            }
        } else {
            println!("  No match");
        }
    }

    Ok(())
}
