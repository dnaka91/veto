use std::{
    fs::File,
    hash::BuildHasher,
    io::{prelude::*, BufReader, Lines},
    net::IpAddr,
    path::PathBuf,
};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use anyhow::Result;
use ipnetwork::IpNetwork;
use log::{debug, info, warn};
use regex::Regex;
use time::OffsetDateTime;

use crate::{
    firewall::{Firewall, Target},
    matcher::Matcher,
    notifier::{Event, EventType},
    settings::Rule,
    storage::TargetRepository,
    HashMap, IndexMap,
};

pub struct Entry {
    pub name: String,
    pub matchers: Vec<Regex>,
    pub blacklists: IndexMap<String, AhoCorasick>,
    pub rule: Rule,
}

pub struct State {
    lines: Option<Lines<BufReader<File>>>,
    pub time: OffsetDateTime,
}

static RULE_REGEXS: phf::Map<&str, &str> = phf::phf_map! {
    "<HOST>" => r"(?P<host>(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[a-fA-F0-9]{0,4}:){1,}[a-fA-F0-9]{1,4})",
    "<TIME>" => r"(?P<time>[0-9]{2}/[a-zA-Z]{3}/[0-9]{4}(?::[0-9]{2}){3} \+[0-9]{4})",
    "<TIME_RFC2822>" => r"(?P<time_rfc2822>[a-zA-Z]{3}, [0-9]{1,2} [a-zA-Z]{3} [0-9]{4} [0-9]{2}(?::[0-9]{2}){2} [\+-][0-9]{4})",
    "<TIME_RFC3339>" => r"(?P<time_rfc3339>[0-9]{4}(?:-[0-9]{2}){2}T[0-9]{2}(?::[0-9]{2}){2}[\+-][0-9]{2}:[0-9]{2})",
    "<METHOD>" => r"(?P<method>GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)",
    "<VERSION>" => r"(?P<version>HTTP/[1-9](?:\.[0-9])?)",
};

pub struct Handler<TR, F> {
    pub whitelist: Vec<IpNetwork>,
    pub storage: TR,
    pub firewall: F,
    pub last_unblock: OffsetDateTime,
}

impl<TR, F> Handler<TR, F>
where
    TR: TargetRepository,
    F: Firewall,
{
    pub fn handle_event(
        &mut self,
        files: &mut HashMap<PathBuf, (Entry, State)>,
        event: Event,
    ) -> Result<()> {
        let (entry, ref mut state) = if let Some(e) = files.get_mut(&event.path) {
            e
        } else {
            return Ok(());
        };

        match event.ty {
            EventType::Modified => {
                debug!("modified");
                self.handle_modified(entry, state)?;
            }
            EventType::Removed => {
                debug!("removed");
                state.lines.take();
            }
            EventType::Created => {
                debug!("created");
                let file = File::open(event.path)?;
                let file = BufReader::new(file);
                state.lines.replace(file.lines());
            }
        }

        Ok(())
    }

    #[allow(clippy::unused_self)]
    pub fn check_lines(&self, entry: &Entry, state: &mut State) -> Option<IpAddr> {
        let State { lines, time } = state;

        let lines = match lines {
            Some(l) => l,
            None => return None,
        };

        let matcher = Matcher::new();

        for line in lines {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    warn!("error reading line: {:?}", e);
                    return None;
                }
            };

            if let Some(addr) = matcher.find(entry, time, &line) {
                return Some(addr);
            }
        }

        None
    }

    pub fn handle_modified(&mut self, entry: &Entry, state: &mut State) -> Result<()> {
        while let Some(addr) = self.check_lines(entry, state) {
            if self.whitelist.iter().any(|wl| wl.contains(addr)) {
                info!("skipping whitelisted {}", addr);
                continue;
            }

            let now = OffsetDateTime::now_utc();

            if !self
                .storage
                .upsert(addr, now + entry.rule.timeout, &entry.rule.file)?
            {
                info!("rule {}: blocking {}", entry.name, addr);

                let target = &Target {
                    ip: addr,
                    ports: &entry.rule.ports,
                };
                if let Err(e) = self.firewall.block(target) {
                    warn!("rule: {}: failed blocking {}: {:?}", entry.name, addr, e);
                }
            }
        }

        Ok(())
    }

    pub fn handle_unblock(&mut self, files: &HashMap<PathBuf, (Entry, State)>) -> Result<()> {
        let now = OffsetDateTime::now_utc();

        if self.last_unblock < now {
            self.storage.iter_outdated(|addr, path| {
                let (entry, _) = if let Some(e) = files.get(path) {
                    e
                } else {
                    return Ok(false);
                };

                info!("rule {}: unblocking {}", entry.name, addr);

                let target = &Target {
                    ip: addr,
                    ports: &entry.rule.ports,
                };
                if let Err(e) = self.firewall.unblock(target) {
                    warn!("failed unblocking {}: {}", addr, e);
                }
                Ok(true)
            })?;

            self.last_unblock = now;
        }

        Ok(())
    }
}

pub fn prepare_rules<S>(
    rules: HashMap<String, Rule, S>,
) -> Result<HashMap<PathBuf, (Entry, State), S>>
where
    S: BuildHasher + Default,
{
    let mut files = HashMap::with_hasher(S::default());

    for (name, mut rule) in rules {
        rule.file = rule.file.canonicalize()?;

        let file = File::open(&rule.file)?;
        let buf = BufReader::new(file);
        let lines = Some(buf.lines());
        let time = OffsetDateTime::UNIX_EPOCH;

        files.insert(
            rule.file.clone(),
            (prepare_rule(name, rule)?, State { lines, time }),
        );
    }

    Ok(files)
}

pub fn prepare_rule(name: String, rule: Rule) -> Result<Entry> {
    let matchers = rule
        .filters
        .iter()
        .map(|f| {
            let f = RULE_REGEXS
                .entries()
                .fold(f.clone(), |f, (k, r)| f.replace(k, r));
            Regex::new(&f).map_err(Into::into)
        })
        .collect::<Result<_>>()?;

    let blacklists = rule
        .blacklists
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .dfa(true)
                    .build(v),
            )
        })
        .collect();

    Ok(Entry {
        name,
        matchers,
        blacklists,
        rule,
    })
}

#[cfg(test)]
mod tests {
    use time::{format_description::well_known::{Rfc2822, Rfc3339}, macros::offset, Date, Month};

    use super::*;

    #[test]
    fn valid_host_match() {
        let r = Regex::new(RULE_REGEXS["<HOST>"]).unwrap();
        assert!(r.is_match("127.0.0.1"));
        assert!(r.is_match("::1"));
    }

    #[test]
    fn valid_time_match() {
        let r = Regex::new(RULE_REGEXS["<TIME>"]).unwrap();
        assert!(r.is_match("04/Jul/2020:11:22:33 +0000"));
    }

    #[test]
    fn valid_time_rfc2822_match() {
        let r = Regex::new(RULE_REGEXS["<TIME_RFC2822>"]).unwrap();
        assert!(r.is_match("Fri, 28 Nov 2014 21:00:09 +0900"));

        let value = r
            .captures("Fri, 28 Nov 2014 21:00:09 +0900")
            .unwrap()
            .name("time_rfc2822")
            .unwrap();

        let got = OffsetDateTime::parse(value.as_str(), &Rfc2822).unwrap();

        let expect = Date::from_calendar_date(2014, Month::November, 28)
            .unwrap()
            .with_hms(21, 0, 9)
            .unwrap()
            .assume_offset(offset!(+9));

        assert_eq!(expect, got);
    }

    #[test]
    fn valid_time_rfc3339_match() {
        let r = Regex::new(RULE_REGEXS["<TIME_RFC3339>"]).unwrap();
        assert!(r.is_match("2014-11-28T21:00:09+09:00"));

        let value = r
            .captures("2014-11-28T21:00:09+09:00")
            .unwrap()
            .name("time_rfc3339")
            .unwrap();

        let got = OffsetDateTime::parse(value.as_str(), &Rfc3339).unwrap();

        let expect = Date::from_calendar_date(2014, Month::November, 28)
        .unwrap()
        .with_hms(21, 0, 9)
        .unwrap()
        .assume_offset(offset!(+9));

        assert_eq!(expect, got);
    }

    #[test]
    fn valid_method_match() {
        let r = Regex::new(RULE_REGEXS["<METHOD>"]).unwrap();
        assert!(r.is_match("GET"));
    }

    #[test]
    fn valid_version_match() {
        let r = Regex::new(RULE_REGEXS["<VERSION>"]).unwrap();
        assert!(r.is_match("HTTP/1.0"));
        assert!(r.is_match("HTTP/1.1"));
        assert!(r.is_match("HTTP/2"));
    }
}
