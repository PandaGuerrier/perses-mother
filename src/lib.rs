//! perses-mother — bibliothèque interne.
//!
//! Le binaire n'est qu'un registre de modules ; tout le reste vit ici. Chaque
//! module du démon implémente [`contracts::ContractBase`] et est lancé par
//! [`starter::run`].

pub mod cache;
pub mod contracts;
pub mod dns;
pub mod filter;
pub mod name;
pub mod sniff;
pub mod starter;
pub mod tls;
pub mod wg;
pub mod wireguard;
