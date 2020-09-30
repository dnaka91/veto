use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::prelude::*;
use serde::{Deserialize, Serialize};

use self::memory::MemoryDatabase;

mod memory;

pub trait TargetRepository {
    fn upsert(&mut self, ip: IpAddr, until: DateTime<Utc>, file: &Path) -> Result<bool>;
    fn remove(&mut self, ip: IpAddr) -> Result<()>;
    fn iter_active<F>(&self, f: F) -> Result<()>
    where
        F: Fn(IpAddr, &Path) -> Result<()>;
    fn iter_outdated<F>(&self, f: F) -> Result<()>
    where
        F: Fn(IpAddr, &Path) -> Result<()>;
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Entry {
    file: PathBuf,
    #[serde(with = "chrono::serde::ts_seconds")]
    until: DateTime<Utc>,
    times: u8,
}

impl Entry {
    const fn new(file: PathBuf, until: DateTime<Utc>) -> Self {
        Self {
            file,
            until,
            times: 0,
        }
    }
}

struct HashMapStorage(MemoryDatabase<IpAddr, Entry>);

impl TargetRepository for HashMapStorage {
    fn upsert(&mut self, ip: IpAddr, until: DateTime<Utc>, file: &Path) -> Result<bool> {
        let mut exists = true;

        self.0.get_mut(|map| {
            map.entry(ip)
                .and_modify(|e| {
                    e.until = until;
                })
                .or_insert_with(|| {
                    exists = false;
                    Entry::new(file.to_owned(), until)
                });
            true
        });

        Ok(exists)
    }

    fn remove(&mut self, ip: IpAddr) -> Result<()> {
        self.0.get_mut(|map| map.remove(&ip).is_some());
        Ok(())
    }

    fn iter_active<F>(&self, f: F) -> Result<()>
    where
        F: Fn(IpAddr, &Path) -> Result<()>,
    {
        let now = Utc::now();

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
        F: Fn(IpAddr, &Path) -> Result<()>,
    {
        let now = Utc::now();

        self.0.get(|map| {
            for (k, v) in map.iter().filter(|(_, v)| v.until < now) {
                f(*k, &v.file)?;
            }
            Ok(())
        })?;

        Ok(())
    }
}

pub fn new_storage(path: Option<PathBuf>) -> Result<impl TargetRepository> {
    Ok(HashMapStorage(MemoryDatabase::new(path)?))
}

fn get_location(path: Option<PathBuf>) -> Result<PathBuf> {
    Ok(if let Some(path) = path {
        path
    } else {
        PathBuf::from("/var/lib/veto/storage.bin")
    })
}
