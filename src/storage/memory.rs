use std::fs;
use std::fs::File;
use std::hash::Hash;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::ops::Drop;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ahash::RandomState;
use anyhow::Result;
use crossbeam_channel::Sender;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use log::{debug, error};
use parking_lot::RwLock;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::HashMap;

pub struct MemoryDatabase<K, V> {
    map: Arc<RwLock<HashMap<K, V>>>,
    dirty: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    stop: Sender<()>,
}

impl<K, V> MemoryDatabase<K, V>
where
    K: Eq + Hash + Serialize + DeserializeOwned + Send + Sync + 'static,
    V: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    pub fn new(path: Option<PathBuf>) -> Result<Self> {
        let location = super::get_location(path)?;
        let map = Arc::new(RwLock::new(if let Ok(f) = File::open(&location) {
            bincode::deserialize_from(GzDecoder::new(BufReader::new(f)))?
        } else {
            HashMap::with_hasher(RandomState::new())
        }));
        let dirty = Arc::new(AtomicBool::new(false));

        let map2 = map.clone();
        let dirty2 = dirty.clone();

        let (stop_tx, stop_rx) = crossbeam_channel::bounded(0);
        let ticker = crossbeam_channel::tick(Duration::from_millis(500));

        #[allow(clippy::useless_transmute)]
        let handle = thread::spawn(move || loop {
            crossbeam_channel::select! {
                recv(stop_rx) -> _ => break,
                recv(ticker) -> _ => {
                    if dirty2.load(Ordering::Relaxed) {
                        if let Err(e) = save(&location, &map2.read()) {
                            error!("Failed saving storage: {:?}", e);
                        }

                        dirty2.store(false, Ordering::Relaxed);
                    }
                }
            }
        });

        Ok(Self {
            map,
            dirty,
            handle: Some(handle),
            stop: stop_tx,
        })
    }

    pub fn get(&self, f: impl Fn(&HashMap<K, V>) -> Result<()>) -> Result<()> {
        f(&self.map.read())
    }

    pub fn get_mut(&self, mut f: impl FnMut(&mut HashMap<K, V>) -> bool) {
        if f(&mut self.map.write()) {
            self.dirty.store(true, Ordering::Relaxed);
        }
    }
}

impl<K, V> Drop for MemoryDatabase<K, V> {
    fn drop(&mut self) {
        self.stop.send(()).unwrap();

        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }

        debug!("storage shut down");

        debug!("storage statistics:");
        debug!("total entries: {}", self.map.read().len());
    }
}

fn save<K, V>(location: &Path, map: &HashMap<K, V>) -> Result<()>
where
    K: Eq + Hash + Serialize,
    V: Serialize,
{
    if let Some(parent) = location.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(location)?;
    let file = BufWriter::new(file);
    let mut file = GzEncoder::new(file, Compression::default());

    bincode::serialize_into(&mut file, map)?;
    file.finish()?.into_inner()?.flush()?;

    Ok(())
}
