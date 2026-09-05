//! Point d'entrée : le registre des modules, et rien d'autre.
//!
//! Le binaire ne prend aucun argument. Il lance la capture et le filtrage de
//! la liste noire, chacun dans son thread, et attend.
//!
//! Réglages, tous facultatifs :
//!
//! | Variable | Défaut | Rôle |
//! | --- | --- | --- |
//! | `PERSES_INTERFACE` | `wg0` | interface WireGuard observée |
//! | `PERSES_DEVICE` | résolu depuis l'interface | périphérique de capture (`utunN` sous macOS) |
//! | `PERSES_BPF_FILTER` | `udp port 53 or tcp port 443` | filtre de capture |
//! | `PERSES_QUEUE` | `0` | numéro de la file NFQUEUE |
//! | `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_DB` | voir `cache::CacheConfig` | accès à Redis |
//!
//! ```sh
//! sudo -E perses-mother
//! ```
//!
//! Ajouter un module : un fichier `module.rs` dans son dossier, une ligne
//! dans le `vec!` ci-dessous.

use std::process::ExitCode;

use perses_mother::contracts::ContractBase;
use perses_mother::filter::Blacklist;
use perses_mother::sniff::Sniffer;
use perses_mother::starter;

fn main() -> ExitCode {
    let modules: Vec<Box<dyn ContractBase>> = vec![
        Box::new(Sniffer::from_env()),
        Box::new(Blacklist::from_env()),
    ];

    starter::run(modules)
}
