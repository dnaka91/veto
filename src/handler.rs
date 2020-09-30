use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, Lines};
use std::net::IpAddr;
use std::path::PathBuf;

use ahash::RandomState;
use aho_corasick::AhoCorasick;
use aho_corasick::AhoCorasickBuilder;
use anyhow::Result;
use chrono::prelude::*;
use ipnetwork::IpNetwork;
use log::{debug, info, trace, warn};
use regex::Regex;

use crate::firewall::{Firewall, Target};
use crate::notifier::{Event, EventType};
use crate::settings::Rule;
use crate::storage::TargetRepository;
use crate::HashMap;

pub struct Entry {
    pub name: String,
    lines: Option<Lines<BufReader<File>>>,
    pub matchers: Vec<Regex>,
    pub blacklists: HashMap<String, AhoCorasick>,
    pub time: DateTime<FixedOffset>,
    pub rule: Rule,
}

const HOST_GROUP: &str = "host";
const TIME_GROUP: &str = "time";
const TIME_FORMAT: &str = "%d/%b/%Y:%T %z";

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
    pub last_unblock: DateTime<Utc>,
}

impl<TR, F> Handler<TR, F>
where
    TR: TargetRepository,
    F: Firewall,
{
    pub fn handle_event(
        &mut self,
        files: &mut HashMap<PathBuf, Entry>,
        event: Event,
    ) -> Result<()> {
        let mut entry = if let Some(e) = files.get_mut(&event.path) {
            e
        } else {
            return Ok(());
        };

        match event.ty {
            EventType::Modified => {
                debug!("modified");
                self.handle_modified(&mut entry)?;
            }
            EventType::Removed => {
                debug!("removed");
                entry.lines.take();
            }
            EventType::Created => {
                debug!("created");
                let file = File::open(event.path)?;
                let file = BufReader::new(file);
                entry.lines.replace(file.lines());
            }
        }

        Ok(())
    }

    #[allow(clippy::unused_self)]
    pub fn check_lines(&self, entry: &mut Entry) -> Option<IpAddr> {
        let lines = match &mut entry.lines {
            Some(l) => l,
            None => return None,
        };

        let now: DateTime<FixedOffset> = Utc::now().into();

        for line in lines {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    warn!("error reading line: {:?}", e);
                    return None;
                }
            };

            for matcher in &entry.matchers {
                if let Some(caps) = matcher.captures(&line) {
                    trace!("captures: {:?}", caps);

                    match caps
                        .name(TIME_GROUP)
                        .and_then(|time| DateTime::parse_from_str(time.as_str(), TIME_FORMAT).ok())
                    {
                        Some(time) => {
                            trace!("time: {}", time);
                            if time < entry.time || now - time > entry.rule.timeout {
                                break;
                            }

                            entry.time = time;
                        }
                        None => continue,
                    }

                    let host = match caps.name(HOST_GROUP).and_then(|v| v.as_str().parse().ok()) {
                        Some(value) => value,
                        None => continue,
                    };

                    if entry.blacklists.is_empty() {
                        return Some(host);
                    }

                    for (name, blacklist) in &entry.blacklists {
                        if let Some(value) = caps.name(name) {
                            let res = blacklist.find(value.as_str());
                            debug!("blacklist '{}': {:?}", name, res);

                            if res.is_some() {
                                return Some(host);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    pub fn handle_modified(&mut self, entry: &mut Entry) -> Result<()> {
        while let Some(addr) = self.check_lines(entry) {
            if self.whitelist.iter().any(|wl| wl.contains(addr)) {
                info!("skipping whitelisted {}", addr);
                continue;
            }

            let now = Utc::now();

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

    pub fn handle_unblock(&mut self, files: &HashMap<PathBuf, Entry>) -> Result<()> {
        let now = Utc::now();

        if self.last_unblock < now {
            self.storage.iter_outdated(|addr, path| {
                let entry = if let Some(e) = files.get(path) {
                    e
                } else {
                    return Ok(());
                };

                info!("rule {}: unblocking {}", entry.name, addr);

                let target = &Target {
                    ip: addr,
                    ports: &entry.rule.ports,
                };
                if let Err(e) = self.firewall.unblock(target) {
                    warn!("failed unblocking {}: {}", addr, e);
                }
                Ok(())
            })?;

            self.last_unblock = now;
        }

        Ok(())
    }
}

pub fn prepare_rules(rules: HashMap<String, Rule>) -> Result<HashMap<PathBuf, Entry>> {
    let mut files = HashMap::with_hasher(RandomState::new());

    for (name, mut rule) in rules {
        rule.file = rule.file.canonicalize()?;

        files.insert(rule.file.clone(), prepare_rule(name, rule)?);
    }

    Ok(files)
}

fn prepare_rule(name: String, rule: Rule) -> Result<Entry> {
    let matchers = rule
        .filters
        .iter()
        .map(|f| {
            let f = RULE_REGEXS
                .entries()
                .fold(f.clone(), |f, (k, r)| f.replace(k, r));
            Regex::new(&f).map_err(Into::into)
        })
        .collect::<Result<Vec<_>>>()?;

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
        .collect::<HashMap<_, _>>();

    let file = File::open(&rule.file)?;
    let buf = BufReader::new(file);
    let lines = Some(buf.lines());
    let time = Utc.fix().timestamp(0, 0);

    Ok(Entry {
        name,
        lines,
        matchers,
        blacklists,
        time,
        rule,
    })
}

#[cfg(test)]
mod tests {
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

        let got = DateTime::parse_from_rfc2822(value.as_str()).unwrap();

        let expect = FixedOffset::east(9 * 3600)
            .ymd(2014, 11, 28)
            .and_hms(21, 0, 9);

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

        let got = DateTime::parse_from_rfc3339(value.as_str()).unwrap();

        let expect = FixedOffset::east(9 * 3600)
            .ymd(2014, 11, 28)
            .and_hms(21, 0, 9);

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
