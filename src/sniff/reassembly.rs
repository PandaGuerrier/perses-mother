//! Recollage des ClientHello coupés en deux par la MTU.
//!
//! Avec les échanges de clés post-quantiques, un ClientHello dépasse souvent
//! 1500 octets — et la MTU d'un tunnel WireGuard est plus basse encore. Le
//! message arrive alors en plusieurs segments TCP, et le SNI se trouve dans
//! le second : le lire exige de garder le premier de côté.
//!
//! Ce n'est pas une pile TCP : on ne regarde ni les numéros de séquence ni
//! les retransmissions, on se contente de concaténer les segments d'un même
//! flux dans leur ordre d'arrivée. C'est suffisant pour une poignée de main
//! qui vient de commencer, et ça tient en mémoire bornée.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::tls::{self, TlsError};

use super::packet::Segment;

/// Nombre de poignées de main suivies simultanément.
const MAX_FLOWS: usize = 512;
/// Octets gardés par flux avant d'abandonner.
const MAX_BUFFERED: usize = 16 * 1024;

/// Les quatre valeurs qui identifient un sens de connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
}

impl From<&Segment<'_>> for FlowKey {
    fn from(segment: &Segment<'_>) -> Self {
        Self {
            src: segment.src,
            dst: segment.dst,
            src_port: segment.src_port,
            dst_port: segment.dst_port,
        }
    }
}

/// Suit les poignées de main en cours pour en extraire le SNI.
#[derive(Debug, Default)]
pub struct ClientHelloTracker {
    pending: HashMap<FlowKey, Vec<u8>>,
}

impl ClientHelloTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Nombre de flux actuellement en attente d'un segment supplémentaire.
    pub fn pending_flows(&self) -> usize {
        self.pending.len()
    }

    /// Examine un segment TCP, et rend le nom d'hôte si le ClientHello est
    /// complet.
    pub fn observe(&mut self, key: FlowKey, payload: &[u8]) -> Option<String> {
        if payload.is_empty() {
            return None;
        }

        let outcome = match self.pending.get_mut(&key) {
            // Ce flux attendait la suite : on la colle et on retente.
            Some(buffer) if buffer.len() + payload.len() <= MAX_BUFFERED => {
                buffer.extend_from_slice(payload);
                tls::server_name(buffer)
            }
            // Trop long pour un ClientHello : ce flux ne nous intéresse plus.
            Some(_) => {
                self.pending.remove(&key);
                return None;
            }
            None => tls::server_name(payload),
        };
        // `outcome` possède son résultat : l'emprunt sur `self.pending`
        // s'arrête ici, ce qui autorise les modifications ci-dessous.

        match outcome {
            Ok(name) => {
                self.pending.remove(&key);
                Some(name)
            }
            // Le ClientHello continue dans le segment suivant : on garde ce
            // qu'on a vu en attendant.
            Err(TlsError::Incomplete) => {
                self.remember(key, payload);
                None
            }
            // Pas une poignée de main, ou mal formée : rien à suivre.
            Err(_) => {
                self.pending.remove(&key);
                None
            }
        }
    }

    fn remember(&mut self, key: FlowKey, payload: &[u8]) {
        if self.pending.contains_key(&key) {
            return; // déjà accumulé par `observe`
        }
        // Table pleine : on libère une place plutôt que d'ignorer les
        // nouvelles connexions indéfiniment.
        if self.pending.len() >= MAX_FLOWS {
            if let Some(victim) = self.pending.keys().next().copied() {
                self.pending.remove(&victim);
            }
        }
        self.pending.insert(key, payload.to_vec());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::client_hello::testing::client_hello;

    fn key(port: u16) -> FlowKey {
        FlowKey {
            src: "10.8.0.2".parse().unwrap(),
            dst: "140.82.121.3".parse().unwrap(),
            src_port: port,
            dst_port: 443,
        }
    }

    #[test]
    fn reads_a_client_hello_that_fits_in_one_segment() {
        let mut tracker = ClientHelloTracker::new();
        let name = tracker.observe(key(51000), &client_hello("github.com"));
        assert_eq!(name.as_deref(), Some("github.com"));
        assert_eq!(tracker.pending_flows(), 0, "rien ne doit rester en attente");
    }

    #[test]
    fn reassembles_a_client_hello_split_by_the_mtu() {
        let hello = client_hello("api.github.com");
        let (first, second) = hello.split_at(hello.len() / 2);

        let mut tracker = ClientHelloTracker::new();
        assert_eq!(tracker.observe(key(51001), first), None);
        assert_eq!(tracker.pending_flows(), 1);
        assert_eq!(
            tracker.observe(key(51001), second).as_deref(),
            Some("api.github.com")
        );
        assert_eq!(tracker.pending_flows(), 0);
    }

    #[test]
    fn keeps_concurrent_handshakes_apart() {
        let github = client_hello("github.com");
        let crates = client_hello("crates.io");
        let (g1, g2) = github.split_at(20);
        let (c1, c2) = crates.split_at(20);

        let mut tracker = ClientHelloTracker::new();
        tracker.observe(key(51002), g1);
        tracker.observe(key(51003), c1);
        assert_eq!(tracker.pending_flows(), 2);
        assert_eq!(
            tracker.observe(key(51003), c2).as_deref(),
            Some("crates.io")
        );
        assert_eq!(
            tracker.observe(key(51002), g2).as_deref(),
            Some("github.com")
        );
    }

    #[test]
    fn application_data_is_not_tracked() {
        let mut tracker = ClientHelloTracker::new();
        assert_eq!(tracker.observe(key(51004), &[0x17, 0x03, 0x03, 0x00, 0x05]), None);
        assert_eq!(tracker.pending_flows(), 0, "un flux déjà chiffré est lâché");
    }

    #[test]
    fn memory_stays_bounded_under_a_flood() {
        let mut tracker = ClientHelloTracker::new();
        let partial = &client_hello("example.com")[..10];
        for port in 0..(MAX_FLOWS as u16 * 2) {
            tracker.observe(key(port), partial);
        }
        assert!(tracker.pending_flows() <= MAX_FLOWS);
    }

    #[test]
    fn a_flow_that_never_completes_is_dropped_past_the_limit() {
        let mut tracker = ClientHelloTracker::new();
        let hello = client_hello("example.com");
        tracker.observe(key(51005), &hello[..10]);
        // Un flux qui déverse des données sans jamais finir son ClientHello.
        for _ in 0..3 {
            tracker.observe(key(51005), &vec![0u8; MAX_BUFFERED / 2]);
        }
        assert_eq!(tracker.pending_flows(), 0);
    }
}
