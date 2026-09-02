//! Module `tls` — lecture du début d'une poignée de main TLS.
//!
//! Seul le ClientHello nous intéresse : il est en clair, et porte le nom
//! d'hôte demandé. Rien n'est déchiffré, rien n'est émis.

pub mod client_hello;

pub use client_hello::{server_name, TlsError};
