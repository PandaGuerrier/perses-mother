//! Module `wg` — pilotage d'un serveur WireGuard.
//!
//! Deux points d'entrée :
//!
//! * [`cold_start`] — provisionnement initial : génération de la paire de clés
//!   Curve25519 du serveur et écriture du fichier `wg-quick`.
//! * [`start`] — montage de l'interface.
//!
//! ```no_run
//! use perses_mother::wg::{self, ServerConfig};
//!
//! let cfg = ServerConfig::default();
//! let provisioning = wg::cold_start(&cfg, false)?;
//! println!("clé publique du serveur: {}", provisioning.public_key);
//! wg::start(&cfg)?;
//! # Ok::<(), wg::WgError>(())
//! ```
//!
//! `start` / `stop` s'appuient sur `wg-quick` et nécessitent donc les droits
//! root ; `cold_start` n'a besoin que d'un accès en écriture à `config_dir`.

pub mod config;
pub mod error;
pub mod keys;
pub mod server;

pub use config::{Peer, ServerConfig, DEFAULT_ADDRESS, DEFAULT_INTERFACE, DEFAULT_LISTEN_PORT};
pub use error::{Result, WgError};
pub use keys::{generate_preshared_key, KeyPair};
pub use server::{
    cold_start, is_running, resolve_device, start, status, stop, Provisioning, StartOutcome,
    Status, StopOutcome,
};
