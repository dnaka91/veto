use std::{
    fs,
    fs::File,
    hash::Hash,
    io::{prelude::*, BufReader, BufWriter},
    ops::Drop,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use ahash::RandomState;
use anyhow::Result;
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use flume::Sender;
use log::{debug, error};
use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Serialize};

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
    pub fn new(path: Option<PathBuf>) -> Self {
        let location = super::get_location(path);
        let map = Arc::new(RwLock::new(File::open(&location).map_or_else(
            |_| HashMap::with_hasher(RandomState::new()),
            |f| bincode::deserialize_from(GzDecoder::new(BufReader::new(f))).unwrap_or_default(),
        )));
        let dirty = Arc::new(AtomicBool::new(false));

        let map2 = map.clone();
        let dirty2 = dirty.clone();

        let (stop_tx, stop_rx) = flume::bounded(0);

        let handle = thread::spawn(move || loop {
            match stop_rx.recv_timeout(Duration::from_millis(500)) {
                Err(_) => break,
                Ok(()) => {
                    if dirty2.load(Ordering::Relaxed) {
                        if let Err(e) = save(&location, &map2.read()) {
                            error!("Failed saving storage: {:?}", e);
                        }

                        dirty2.store(false, Ordering::Relaxed);
                    }
                }
            }
        });

        Self {
            map,
            dirty,
            handle: Some(handle),
            stop: stop_tx,
        }
    }

    pub fn get(&self, f: impl Fn(&HashMap<K, V>) -> Result<()>) -> Result<()> {
        f(&self.map.read())
    }

    pub fn get_mut(&self, mut f: impl FnMut(&mut HashMap<K, V>) -> Result<bool>) -> Result<()> {
        if f(&mut self.map.write())? {
            self.dirty.store(true, Ordering::Relaxed);
        }
        Ok(())
    }
}

impl<K, V> Drop for MemoryDatabase<K, V> {
    fn drop(&mut self) {
        self.stop.send(()).ok();

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
