#![deny(unsafe_code, rust_2018_idioms, clippy::all, clippy::pedantic)]
#![warn(clippy::nursery)]

use std::env;
use std::path::PathBuf;
use std::time::Duration as StdDuration;

use anyhow::Result;
use chrono::prelude::*;
use chrono::Duration;
use clap::{AppSettings, Clap};
use crossbeam_channel::Receiver;
use log::{info, warn};

use veto::firewall::{self, Firewall};
use veto::handler;
use veto::handler::Handler;
use veto::notifier;
use veto::settings;
use veto::storage;
use veto::storage::TargetRepository;

/// A lightweight, log file based IP blocker with focus on simplicity and speed.
#[derive(Clap)]
#[clap(about, author, setting = AppSettings::ColoredHelp)]
struct Opts {
    /// Level of verbosity.
    ///
    /// Pass the flag once (-v) for slight verbosity with informative logs. Pass it twice (-vv) to
    /// include debug information as well. Pass it trice (-vvv) or more to be super verbose and log
    /// as much as possible.
    #[clap(short, long, parse(from_occurrences))]
    verbose: u8,
    /// Alternative configuration location.
    #[clap(long, env = "VETO_CONFIG")]
    config: Option<PathBuf>,
    /// Alternative storage location.
    #[clap(long, env = "VETO_STORAGE")]
    storage: Option<PathBuf>,
    #[clap(subcommand)]
    cmd: Option<Command>,
}

#[derive(Clap)]
enum Command {
    /// Remove any leftover firewall rules.
    Uninstall,
}

fn main() -> Result<()> {
    dotenv::dotenv().ok();

    let opts = Opts::parse();

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

    if let Some(Command::Uninstall) = opts.cmd {
        firewall::IpSet::new()?.uninstall()?;
        return Ok(());
    }

    let settings = settings::load(opts.config)?;

    let shutdown = create_shutdown()?;

    let firewall = firewall::IpSet::new()?;

    let storage = storage::new_storage(opts.storage)?;

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
                warn!("failed blocking {}: {:?}", addr, e)
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
        crossbeam_channel::select! {
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
