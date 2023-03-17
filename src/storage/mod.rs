use std::{
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use self::memory::MemoryDatabase;

mod memory;

/// Repository that keeps information about all IPs that have ever been blocked by the application.
/// It helps to determine when to remove items from the blocklist again and holds basic statistics.
pub trait TargetRepository {
    /// Insert a new entry into the repository or update it if it already exists.
    fn upsert(&mut self, ip: IpAddr, until: OffsetDateTime, file: &Path) -> Result<bool>;

    /// Remove an entry by its IP address from the repository.
    fn remove(&mut self, ip: IpAddr) -> Result<()>;

    /// Iterate over all active entries, not modifying there status in any way.
    fn iter_active<F>(&self, f: F) -> Result<()>
    where
        F: Fn(IpAddr, &Path) -> Result<()>;

    /// Iterate over all outdated but still active entries. The outcome of the given function tells
    /// whether an entry should be marked as inactive.
    fn iter_outdated<F>(&self, f: F) -> Result<()>
    where
        F: Fn(IpAddr, &Path) -> Result<bool>;
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Entry {
    /// Location of the log file that this entry came from.
    file: PathBuf,
    /// Timestamp until when this entry should be put on the blocklist.
    #[serde(with = "time::serde::timestamp")]
    until: OffsetDateTime,
    /// Flag that tells whether the current entry is still active, meaning it's still excpected to
    /// be on the blocklist. This is independent of the [`until`] field and caters for state where
    /// an entry is already expired but wasn't removed from the blocklist yet.
    active: bool,
    /// Total amount of times that this entry was already put on the blocklist.
    times: u8,
}

impl Entry {
    /// Create a new basic entry with file origin and the timestamp until when it will be blocked.
    /// The entry is considered active, which means it is expected to be already on the blocklist.
    const fn new(file: PathBuf, until: OffsetDateTime) -> Self {
        Self {
            file,
            until,
            active: true,
            times: 0,
        }
    }
}

/// An implementation of [`TargetRepository`] that keeps all information in a in-memory hash map and
/// periodically saves the state to disk.
struct HashMapStorage(MemoryDatabase<IpAddr, Entry>);

impl TargetRepository for HashMapStorage {
    fn upsert(&mut self, ip: IpAddr, until: OffsetDateTime, file: &Path) -> Result<bool> {
        let mut exists = true;

        self.0.get_mut(|map| {
            map.entry(ip)
                .and_modify(|e| {
                    e.until = until;
                    e.active = true;
                })
                .or_insert_with(|| {
                    exists = false;
                    Entry::new(file.to_owned(), until)
                });
            Ok(true)
        })?;

        Ok(exists)
    }

    fn remove(&mut self, ip: IpAddr) -> Result<()> {
        self.0.get_mut(|map| Ok(map.remove(&ip).is_some()))
    }

    fn iter_active<F>(&self, f: F) -> Result<()>
    where
        F: Fn(IpAddr, &Path) -> Result<()>,
    {
        let now = OffsetDateTime::now_utc();

        self.0.get(|map| {
            for (k, v) in map.iter().filter(|(_, v)| v.until >= now) {
                f(*k, &v.file)?;
            }
            Ok(())
        })?;

        Ok(())
    }

    fn iter_outdated<F>(&self, f: F) -> Result<()>
    where
        F: Fn(IpAddr, &Path) -> Result<bool>,
    {
        let now = OffsetDateTime::now_utc();

        self.0.get_mut(|map| {
            let mut changed = false;
            for (k, v) in map.iter_mut().filter(|(_, v)| v.until < now && v.active) {
                if f(*k, &v.file)? {
                    v.active = false;
                    changed = true;
                }
            }
            Ok(changed)
        })?;

        Ok(())
    }
}

/// Create a new [`TargetRepository`] with the default implementation.
#[must_use]
pub fn new_storage(path: Option<PathBuf>) -> impl TargetRepository {
    HashMapStorage(MemoryDatabase::new(path))
}

/// Determine the location of a file for persistence.
fn get_location(path: Option<PathBuf>) -> PathBuf {
    path.unwrap_or_else(|| PathBuf::from("/var/lib/veto/storage.bin"))
}
