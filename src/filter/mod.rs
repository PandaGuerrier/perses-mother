//! Module `filter` — coupe les connexions vers les domaines de la liste noire.
//!
//! Le trafic du tunnel est dérouté vers une file NFQUEUE ; pour chaque paquet,
//! le noyau attend notre verdict. On y lit le SNI du ClientHello, on consulte
//! la liste noire dans Redis, et on tranche.
//!
//! Poser la règle avant de lancer la commande :
//!
//! ```sh
//! iptables -I FORWARD -i wg0 -p tcp --dport 443 -j NFQUEUE --queue-num 0
//! ```
//!
//! et la retirer ensuite avec la même ligne en `-D`. Sans programme à l'écoute
//! de la file, les paquets qu'elle reçoit sont perdus : ne pas laisser la
//! règle en place après avoir arrêté le filtre.
//!
//! La décision ([`Policy`]) est séparée de la file ([`queue`]) : la première
//! est portable et testée, la seconde n'existe que sous Linux.

pub mod module;
pub mod policy;
pub mod queue;

pub use module::Blacklist;
pub use policy::{Decision, Policy, Verdict, BLACKLIST_SET, SEEN_SET};
pub use queue::{filter, iptables_rule, FilterConfig, FilterError, DEFAULT_QUEUE};
