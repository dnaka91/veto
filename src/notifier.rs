use std::path::PathBuf;

use anyhow::Result;
use crossbeam_channel::{Receiver, Sender};
use log::{debug, trace, warn};
use notify::event::{EventKind, ModifyKind};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};

pub fn start<'a>(paths: impl Iterator<Item = &'a PathBuf>) -> Result<Notifier> {
    let (tx, rx) = crossbeam_channel::unbounded();
    let handler = Handler { tx };

    let mut watcher = notify::immediate_watcher(move |res| handler.handle(res))?;

    for path in paths {
        debug!("Start watching file {:?}", path);
        watcher.watch(path, RecursiveMode::NonRecursive)?;
    }

    Ok(Notifier {
        rx,
        _watcher: watcher,
    })
}

pub struct Notifier {
    pub rx: Receiver<Event>,
    // Not used but has to be kept around or otherwise it would be dropped.
    _watcher: RecommendedWatcher,
}

pub struct Event {
    pub path: PathBuf,
    pub ty: EventType,
}

pub enum EventType {
    Modified,
    Removed,
    Created,
}

struct Handler {
    tx: Sender<Event>,
}

impl Handler {
    /// Handle events from the underlying notification system and boil the down to a simpler
    /// [`EventType`] that only represents the events we care about.
    fn handle(&self, event: notify::Result<notify::Event>) {
        match event {
            Ok(event) => {
                trace!("{:?}", event);

                let notify::Event { paths, kind, .. } = event;

                paths
                    .into_iter()
                    .filter_map(|path| {
                        let ty = match kind {
                            EventKind::Modify(ModifyKind::Data(_)) => Some(EventType::Modified),
                            EventKind::Modify(ModifyKind::Name(_)) => Some(if path.exists() {
                                EventType::Created
                            } else {
                                EventType::Removed
                            }),
                            EventKind::Remove(_) => Some(EventType::Removed),
                            EventKind::Create(_) => Some(EventType::Created),
                            _ => None,
                        };
                        ty.map(|ty| Event { path, ty })
                    })
                    .for_each(|event| self.tx.send(event).unwrap())
            }
            Err(e) => warn!("watch error: {:?}", e),
        }
    }
}
