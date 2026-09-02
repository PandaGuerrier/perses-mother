//! Capture passive du trafic d'une interface, via libpcap.

use std::convert::Infallible;
use std::io::{self, Write};

use crate::dns;

use super::packet::{self, LinkType, Segment, Transport};
use super::reassembly::ClientHelloTracker;

/// Port du service DNS.
pub const DNS_PORT: u16 = 53;
/// Filtre BPF appliqué dans le noyau : seul ce trafic remonte jusqu'à nous.
///
/// Deux sources de noms : les requêtes DNS en clair, et le SNI des poignées
/// de main TLS — celui-ci reste lisible même quand le client chiffre son DNS
/// (DoH/DoT), ce qui est devenu le cas par défaut.
pub const DEFAULT_FILTER: &str = "udp port 53 or tcp port 443";
/// Octets conservés par paquet — de quoi couvrir un datagramme DNS complet.
const SNAPLEN: i32 = 2048;
/// Délai avant que libpcap ne rende la main sans paquet, en millisecondes.
const READ_TIMEOUT_MS: i32 = 500;

#[derive(Debug, thiserror::Error)]
pub enum SniffError {
    #[error("droits insuffisants pour capturer sur {0} — relancer avec sudo")]
    PermissionDenied(String),
    #[error("capture impossible sur {device}: {source}")]
    Open {
        device: String,
        #[source]
        source: pcap::Error,
    },
    #[error("filtre BPF refusé ({filter}): {source}")]
    Filter {
        filter: String,
        #[source]
        source: pcap::Error,
    },
    #[error("couche liaison non gérée sur {device}: DLT {dlt}")]
    UnsupportedLink { device: String, dlt: i32 },
    #[error("capture interrompue: {0}")]
    Capture(#[source] pcap::Error),
}

/// Quoi écouter, et quoi en retenir.
#[derive(Debug, Clone)]
pub struct SniffConfig {
    /// Interface système à capturer (`utun11` sous macOS, `wg0` sous Linux).
    pub device: String,
    /// Filtre BPF, évalué dans le noyau avant toute copie vers l'espace
    /// utilisateur : c'est lui qui fait le gros du tri.
    pub filter: String,
}

impl SniffConfig {
    pub fn new(device: impl Into<String>) -> Self {
        Self {
            device: device.into(),
            filter: DEFAULT_FILTER.to_string(),
        }
    }
}

/// Écoute l'interface et écrit sur stdout le nom demandé par chaque requête DNS.
///
/// Ne rend la main qu'en cas d'erreur fatale : le type de succès est
/// [`Infallible`], un type qui n'a aucune valeur possible.
pub fn sniff(cfg: &SniffConfig) -> Result<Infallible, SniffError> {
    let mut capture = open(cfg)?;

    let dlt = capture.get_datalink();
    let link = LinkType::from_raw(dlt.0).ok_or_else(|| SniffError::UnsupportedLink {
        device: cfg.device.clone(),
        dlt: dlt.0,
    })?;

    // Les traces vont sur stderr : stdout ne contient que des noms de domaine,
    // pour rester utilisable dans un pipe (`… | sort -u`).
    eprintln!("capture sur {} ({link:?}) — filtre: {}", cfg.device, cfg.filter);

    let mut tracker = ClientHelloTracker::new();
    loop {
        let frame = match capture.next_packet() {
            Ok(frame) => frame,
            // Aucun paquet pendant le délai de lecture : ce n'est pas une erreur.
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(SniffError::Capture(e)),
        };
        if let Some(name) = domain_of(link, frame.data, &mut tracker) {
            print_name(&name);
        }
    }
}

fn open(cfg: &SniffConfig) -> Result<pcap::Capture<pcap::Active>, SniffError> {
    let mut capture = pcap::Capture::from_device(cfg.device.as_str())
        .and_then(|device| {
            device
                .snaplen(SNAPLEN)
                .promisc(false)
                // Sans ce mode, BPF attend d'avoir rempli son tampon avant de
                // nous réveiller : les noms sortiraient par paquets, en retard.
                .immediate_mode(true)
                .timeout(READ_TIMEOUT_MS)
                .open()
        })
        .map_err(|source| open_error(&cfg.device, source))?;

    capture
        .filter(&cfg.filter, true)
        .map_err(|source| SniffError::Filter {
            filter: cfg.filter.clone(),
            source,
        })?;
    Ok(capture)
}

/// libpcap ne rapporte le refus de droits que dans le texte de l'erreur :
/// on le reconnaît pour pouvoir dire quoi faire plutôt que de le recopier.
fn open_error(device: &str, source: pcap::Error) -> SniffError {
    let text = source.to_string();
    if text.contains("Permission denied") || text.contains("Operation not permitted") {
        return SniffError::PermissionDenied(device.to_string());
    }
    SniffError::Open {
        device: device.to_string(),
        source,
    }
}

/// Rend le nom de domaine porté par une trame, s'il y en a un.
///
/// Deux cas : une requête DNS en clair, ou le SNI d'un ClientHello TLS.
fn domain_of(link: LinkType, frame: &[u8], tracker: &mut ClientHelloTracker) -> Option<String> {
    let segment = packet::segment(link, frame)?;
    match segment.protocol {
        Transport::Udp => dns_name(&segment),
        Transport::Tcp => tracker.observe((&segment).into(), segment.payload),
    }
}

/// Nom demandé par une requête DNS.
///
/// Les réponses sont écartées par [`dns::parse_query`] : sans cela, chaque nom
/// apparaîtrait deux fois.
fn dns_name(segment: &Segment<'_>) -> Option<String> {
    if segment.dst_port != DNS_PORT {
        return None;
    }
    dns::parse_query(segment.payload).ok().map(|q| q.name)
}

/// Écrit un nom sur stdout, immédiatement.
fn print_name(name: &str) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    // Sortie redirigée vers un fichier ou un pipe : sans vidage explicite, les
    // noms resteraient bloqués dans le tampon.
    if writeln!(out, "{name}").is_ok() {
        let _ = out.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::message::testing::query;
    use crate::sniff::packet::testing::{null_ipv4_tcp, null_ipv4_udp};
    use crate::tls::client_hello::testing::client_hello;

    fn domain(frame: &[u8]) -> Option<String> {
        domain_of(LinkType::Null, frame, &mut ClientHelloTracker::new())
    }

    #[test]
    fn reads_the_domain_out_of_a_captured_query() {
        let frame = null_ipv4_udp(51234, DNS_PORT, &query(0x1234, "www.rust-lang.org"));
        assert_eq!(domain(&frame).as_deref(), Some("www.rust-lang.org"));
    }

    #[test]
    fn reads_the_sni_out_of_a_captured_client_hello() {
        let frame = null_ipv4_tcp(51234, 443, &client_hello("api.github.com"));
        assert_eq!(domain(&frame).as_deref(), Some("api.github.com"));
    }

    #[test]
    fn reads_the_sni_of_a_client_hello_split_across_two_frames() {
        let hello = client_hello("github.com");
        let (first, second) = hello.split_at(hello.len() / 2);
        let mut tracker = ClientHelloTracker::new();

        let frame = null_ipv4_tcp(51234, 443, first);
        assert_eq!(domain_of(LinkType::Null, &frame, &mut tracker), None);

        let frame = null_ipv4_tcp(51234, 443, second);
        assert_eq!(
            domain_of(LinkType::Null, &frame, &mut tracker).as_deref(),
            Some("github.com")
        );
    }

    #[test]
    fn encrypted_traffic_yields_nothing() {
        // Un record « application data » : la poignée de main est déjà finie.
        let frame = null_ipv4_tcp(51234, 443, &[0x17, 0x03, 0x03, 0x01, 0x00]);
        assert_eq!(domain(&frame), None);
    }

    #[test]
    fn skips_responses_so_each_name_appears_once() {
        let mut response = query(0x1234, "example.com");
        response[2] |= 0x80; // QR = 1
        // Une réponse va du port 53 vers le client.
        let frame = null_ipv4_udp(DNS_PORT, 51234, &response);
        assert_eq!(domain(&frame), None);
    }

    #[test]
    fn skips_udp_traffic_that_is_not_dns() {
        let frame = null_ipv4_udp(51234, 443, b"quic, pas du dns");
        assert_eq!(domain(&frame), None);
    }

    #[test]
    fn a_garbage_payload_on_port_53_is_ignored() {
        let frame = null_ipv4_udp(51234, DNS_PORT, b"\xff\xff");
        assert_eq!(domain(&frame), None);
    }
}
