//! Module `cache` — tous les accès à Redis.
//!
//! Le serveur tourne dans le `compose.yaml` à la racine du dépôt :
//!
//! ```sh
//! docker compose up -d redis
//! ```
//!
//! ```no_run
//! use perses_mother::cache::{Cache, CacheConfig};
//!
//! let mut cache = Cache::connect(CacheConfig::from_env()?)?;
//! if cache.add_to_set("visited", "github.com")? {
//!     println!("premier passage sur ce domaine");
//! }
//! println!("{} domaines connus", cache.set_len("visited")?);
//! # Ok::<(), perses_mother::cache::CacheError>(())
//! ```
//!
//! Les clés sont préfixées par [`CacheConfig::namespace`] : `visited` devient
//! `perses:visited`.

pub mod client;
pub mod config;
pub mod error;

pub use client::Cache;
pub use config::{CacheConfig, DEFAULT_HOST, DEFAULT_NAMESPACE, DEFAULT_PORT};
pub use error::{CacheError, Result};
