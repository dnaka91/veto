#![allow(clippy::inline_always, clippy::option_if_let_else)]

use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use regex::Captures;
use time::{format_description::FormatItem, macros::format_description, OffsetDateTime};

use crate::{handler::Entry, settings::Rule, IndexMap};

const HOST_GROUP: &str = "host";
const TIME_GROUP: &str = "time";
const TIME_FORMAT: &[FormatItem<'_>] = format_description!(
    "[day]/[month repr:short]/[year]:[hour][minute][second] [offset_hour][offset_minute]"
);

pub struct Matcher {
    now: OffsetDateTime,
}

impl Default for Matcher {
    fn default() -> Self {
        Self {
            now: OffsetDateTime::now_utc(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Analysis {
    pub matches: IndexMap<String, Option<Match>>,
}

#[derive(Debug)]
pub struct Match {
    pub time: Option<(OffsetDateTime, bool)>,
    pub host: Option<IpAddr>,
    pub captures: IndexMap<String, Option<String>>,
    pub blacklists: IndexMap<String, String>,
}

impl Matcher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // Only used for benchmarks, don't use directly.
    #[must_use]
    pub const fn with(now: OffsetDateTime) -> Self {
        Self { now }
    }

    pub fn find(
        &self,
        entry: &Entry,
        last_time: &mut OffsetDateTime,
        line: &str,
    ) -> Option<IpAddr> {
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

                if Self::match_blacklists(&caps, &entry.blacklists)
                    .next()
                    .is_some()
                {
                    return Some(host);
                }
            }
        }

        None
    }

    #[must_use]
    pub fn find_analyze(&self, entry: &Entry, line: &str) -> Analysis {
        let mut analysis = Analysis::default();

        for (i, matcher) in entry.matchers.iter().enumerate() {
            let matcher_name = entry.rule.filters[i].clone();

            if let Some(caps) = matcher.captures(line) {
                let time = Self::match_time(&caps).map(|time| {
                    (
                        time,
                        self.is_outdated(&entry.rule, OffsetDateTime::UNIX_EPOCH, time),
                    )
                });

                let host = Self::match_host(&caps);

                let blacklists = Self::match_blacklists(&caps, &entry.blacklists)
                    .map(|(bl, p)| (bl.to_owned(), entry.rule.blacklists[bl][p].clone()))
                    .collect();

                analysis.matches.insert(
                    matcher_name,
                    Some(Match {
                        time,
                        host,
                        captures: matcher
                            .capture_names()
                            .filter_map(|name| {
                                name.map(|n| {
                                    (n.to_owned(), caps.name(n).map(|m| m.as_str().to_owned()))
                                })
                            })
                            .collect(),
                        blacklists,
                    }),
                );
            } else {
                analysis.matches.insert(matcher_name, None);
            }
        }

        analysis
    }

    #[inline(always)]
    fn is_outdated(&self, rule: &Rule, last_time: OffsetDateTime, time: OffsetDateTime) -> bool {
        time < last_time || self.now - time > rule.timeout
    }

    #[inline(always)]
    fn match_time(caps: &Captures<'_>) -> Option<OffsetDateTime> {
        caps.name(TIME_GROUP).and_then(|time| {
            OffsetDateTime::parse(time.as_str(), TIME_FORMAT)
                .map(Into::into)
                .ok()
        })
    }

    #[inline(always)]
    fn match_host(caps: &Captures<'_>) -> Option<IpAddr> {
        caps.name(HOST_GROUP)
            .and_then(|host| host.as_str().parse().ok())
    }

    #[inline(always)]
    fn match_blacklists<'a>(
        caps: &'a Captures<'a>,
        blacklists: &'a IndexMap<String, AhoCorasick>,
    ) -> impl Iterator<Item = (&'a str, usize)> + 'a {
        blacklists.iter().filter_map(move |(name, blacklist)| {
            if let Some(value) = caps.name(name) {
                blacklist
                    .find(value.as_str())
                    .map(|m| (name.as_str(), m.pattern().as_usize()))
            } else {
                None
            }
        })
    }
}
