#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, clippy::all, clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions
)]

pub mod firewall;
pub mod handler;
pub mod matcher;
pub mod notifier;
pub mod settings;
pub mod storage;

type HashMap<K, V, S = ahash::RandomState> = std::collections::HashMap<K, V, S>;
type IndexMap<K, V, S = ahash::RandomState> = indexmap::IndexMap<K, V, S>;
type IndexSet<T, S = ahash::RandomState> = indexmap::IndexSet<T, S>;
