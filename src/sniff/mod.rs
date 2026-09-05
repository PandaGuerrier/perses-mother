//! Module `sniff` — écoute passive d'une interface réseau.
//!
//! Branché sur l'interface du tunnel, il affiche les noms de domaine que les
//! clients résolvent. Rien n'est émis sur le réseau, rien n'est modifié : le
//! trafic est seulement observé au passage.
//!
//! ```no_run
//! use perses_mother::cache::{Cache, CacheConfig};
//! use perses_mother::sniff::{self, SniffConfig};
//!
//! // Sous macOS l'interface logique `wg0` est un `utunN` : c'est ce nom-là
//! // qu'attend la capture (voir `wg::resolve_device`).
//! let cache = Cache::connect(CacheConfig::from_env()?)?;
//! sniff::sniff(&SniffConfig::new("utun11"), cache)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Nécessite les droits root : la capture passe par `/dev/bpf` (macOS) ou
//! `AF_PACKET` (Linux).

pub mod capture;
pub mod module;
pub mod packet;
pub mod reassembly;

pub use capture::{sniff, SniffConfig, SniffError, DEFAULT_FILTER, DNS_PORT};
pub use module::Sniffer;
pub use packet::{segment, LinkType, Segment, Transport};
pub use reassembly::{ClientHelloTracker, FlowKey};
