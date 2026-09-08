//! Module `dns` — le protocole DNS, lu puis servi.
//!
//! Deux moitiés :
//!
//! * [`message`] décode une requête et fabrique le refus qu'on lui oppose ;
//! * [`server`] écoute sur l'adresse du tunnel, consulte [`policy`], et rend
//!   soit la réponse du résolveur amont, soit un NXDOMAIN.
//!
//! Le module est aussi la source de noms de la capture ([`crate::sniff`]),
//! qui, elle, ne fait qu'observer.
//!
//! ```no_run
//! use perses_mother::cache::{Cache, CacheConfig};
//! use perses_mother::dns::{DnsConfig, Policy, self};
//!
//! // L'adresse du serveur dans le tunnel : les pairs, et personne d'autre.
//! let cfg = DnsConfig::new("10.8.0.1:53".parse()?);
//! let policy = Policy::new(Cache::connect(CacheConfig::from_env()?)?);
//! dns::serve(&cfg, policy)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Écouter sur le port 53 demande les droits root.

pub mod message;
pub mod module;
pub mod policy;
pub mod server;

pub use message::{id, nxdomain, parse_query, ParseError, Query, RCODE_NXDOMAIN};
pub use module::Resolver;
pub use policy::{Decision, Policy, Verdict};
pub use server::{serve, DnsConfig, DnsError, DEFAULT_UPSTREAM, DNS_PORT};
