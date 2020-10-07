use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use chrono::prelude::*;
use regex::Captures;

use crate::handler::Entry;
use crate::settings::Rule;
use crate::HashMap;

const HOST_GROUP: &str = "host";
const TIME_GROUP: &str = "time";
const TIME_FORMAT: &str = "%d/%b/%Y:%T %z";

pub struct Matcher {
    now: DateTime<Utc>,
}

impl Matcher {
    pub fn new() -> Self {
        Self { now: Utc::now() }
    }

    pub fn find(&self, entry: &Entry, last_time: &mut DateTime<Utc>, line: &str) -> Option<IpAddr> {
        for matcher in &entry.matchers {
            if let Some(caps) = matcher.captures(line) {
                match Self::match_time(&caps) {
                    Some(time) => {
                        if self.is_outdated(&entry.rule, *last_time, time) {
                            break;
                        }

                        *last_time = time;
                    }
                    None => continue,
                }

                let host = match Self::match_host(&caps) {
                    Some(host) => host,
                    None => continue,
                };

                if Self::match_blacklists(&caps, &entry.blacklists).is_some() {
                    return Some(host);
                }
            }
        }

        None
    }

    fn is_outdated(&self, rule: &Rule, last_time: DateTime<Utc>, time: DateTime<Utc>) -> bool {
        time < last_time || self.now - time > rule.timeout
    }

    fn match_time(caps: &Captures<'_>) -> Option<DateTime<Utc>> {
        caps.name(TIME_GROUP).and_then(|time| {
            DateTime::parse_from_str(time.as_str(), TIME_FORMAT)
                .map(Into::into)
                .ok()
        })
    }

    fn match_host(caps: &Captures<'_>) -> Option<IpAddr> {
        caps.name(HOST_GROUP)
            .and_then(|host| host.as_str().parse().ok())
    }

    fn match_blacklists(
        caps: &Captures<'_>,
        blacklists: &HashMap<String, AhoCorasick>,
    ) -> Option<usize> {
        if blacklists.is_empty() {
            return None;
        }

        for (name, blacklist) in blacklists {
            if let Some(value) = caps.name(name) {
                let res = blacklist.find(value.as_str());
                if res.is_some() {
                    return res.map(|m| m.pattern());
                }
            }
        }

        None
    }
}
