//! Module `dns` — décodage du protocole DNS.
//!
//! Ne fait que lire : les paquets viennent de la capture réseau
//! ([`crate::sniff`]), rien n'est émis.

pub mod message;

pub use message::{parse_query, ParseError, Query};
