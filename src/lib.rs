#![deny(unsafe_code, rust_2018_idioms, clippy::all, clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use ahash::RandomState;

pub mod firewall;
pub mod handler;
pub mod matcher;
pub mod notifier;
pub mod settings;
pub mod storage;

type HashMap<K, V, S = RandomState> = std::collections::HashMap<K, V, S>;
type HashSet<T, S = RandomState> = std::collections::HashSet<T, S>;
