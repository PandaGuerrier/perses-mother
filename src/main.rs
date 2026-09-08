//! Point d'entrée : le registre des modules, et rien d'autre.
//!
//! Le binaire ne prend aucun argument. Il lance la capture, le filtrage de la
//! liste noire et le relais DNS, chacun dans son thread, et attend.
//!
//! Réglages, tous facultatifs :
//!
//! | Variable | Défaut | Rôle |
//! | --- | --- | --- |
//! | `PERSES_INTERFACE` | `wg0` | interface WireGuard observée |
//! | `PERSES_DEVICE` | résolu depuis l'interface | périphérique de capture (`utunN` sous macOS) |
//! | `PERSES_BPF_FILTER` | `udp port 53 or tcp port 443` | filtre de capture |
//! | `PERSES_QUEUE` | `0` | numéro de la file NFQUEUE |
//! | `PERSES_DNS_BIND` | adresse de l'interface, port 53 | où le relais DNS écoute |
//! | `PERSES_DNS_UPSTREAM` | `1.1.1.1:53` | résolveur interrogé pour les noms autorisés |
//! | `PERSES_DNS_TIMEOUT`, `PERSES_DNS_WORKERS`, `PERSES_DNS_QUEUE` | `3`, `4`, `256` | voir `dns::server` |
//! | `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_DB` | voir `cache::CacheConfig` | accès à Redis |
//! | `PERSES_SOCKET` | `/tmp/perses.socket` | fichier où les rapports sont écrits, une ligne chacun |
//! | `PERSES_REPORT_QUEUE`, `PERSES_PEERS_TTL` | voir `report::ReportConfig` | écriture des rapports |
//!
//! ```sh
//! sudo -E perses-mother
//! ```
//!
//! Ajouter un module : un fichier `module.rs` dans son dossier, une ligne
//! dans le `vec!` ci-dessous.

use std::process::ExitCode;
use dotenvy::dotenv;
use perses_mother::contracts::ContractBase;
use perses_mother::dns::Resolver;
use perses_mother::filter::Blacklist;
use perses_mother::sniff::Sniffer;
use perses_mother::starter;

fn main() -> ExitCode {
    dotenv().ok();

    let modules: Vec<Box<dyn ContractBase>> = vec![
        Box::new(Sniffer::from_env()),
        Box::new(Blacklist::from_env()),
        Box::new(Resolver::from_env()),
    ];

    starter::run(modules)
}
