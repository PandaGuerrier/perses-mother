//! Module `report` — signalement des domaines connus au collecteur local.
//!
//! Quand la capture croise un domaine que le cache connaît, ce module écrit
//! une ligne de JSON dans `/tmp/perses.socket` décrivant *qui* l'a demandé :
//! la clé publique du pair WireGuard, son endpoint, ses compteurs, ainsi que
//! l'interface qui l'a vu passer.
//!
//! Le chemin peut être une socket Unix — un collecteur écoute à l'autre bout
//! — ou un simple fichier : on tente la socket, puis l'ajout en fin de
//! fichier. Dans les deux cas, un rapport = une ligne, terminée par `\n`.
//!
//! L'écriture se fait dans son propre thread, derrière une file bornée : la
//! boucle de capture dépose et repart, sans jamais attendre la sortie.
//!
//! Réglages, tous par l'environnement :
//!
//! | Variable | Défaut | Rôle |
//! | --- | --- | --- |
//! | `PERSES_SOCKET` | `/tmp/perses.socket` | où les rapports sont écrits |
//! | `PERSES_REPORT_QUEUE` | `256` | rapports en attente avant d'en jeter |
//! | `PERSES_PEERS_TTL` | `5` | fraîcheur de `wg show … dump`, en secondes |
//!
//! ```no_run
//! use perses_mother::report::{Observation, Reporter};
//!
//! let reporter = Reporter::from_env("wg0");
//! reporter.report(Observation::now("ads.example.com", "10.8.0.2".parse()?));
//! # Ok::<(), std::net::AddrParseError>(())
//! ```

pub mod client;
pub mod config;
pub mod json;

pub use client::{payload, Observation, Reporter};
pub use config::{ReportConfig, DEFAULT_SOCKET};
