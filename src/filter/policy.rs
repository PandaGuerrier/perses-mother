//! La décision : laisser passer, ou couper.
//!
//! Ce module ne touche ni au noyau ni au réseau — il reçoit des octets et
//! rend un verdict. C'est ce qui le rend testable sur n'importe quelle
//! plateforme, alors que la file NFQUEUE qui l'alimente est propre à Linux.

use crate::cache::Cache;
use crate::sniff::packet::{self, LinkType};
use crate::sniff::reassembly::{ClientHelloTracker, FlowKey};
use crate::sniff::Transport;

use std::collections::HashSet;

/// Ensemble Redis consulté pour chaque poignée de main.
pub const BLACKLIST_SET: &str = "blacklist";
/// Ensemble Redis où sont notés les domaines observés.
pub const SEEN_SET: &str = "seen";
/// Nombre de flux coupés dont on garde le souvenir.
const MAX_BLOCKED_FLOWS: usize = 4096;

/// Ce qu'on répond au noyau pour un paquet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Le paquet poursuit sa route.
    Accept,
    /// Le paquet est jeté ; l'émetteur ne reçoit rien.
    Drop,
}

/// Ce qui a été décidé, et pourquoi — de quoi journaliser sans deviner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    /// Nom d'hôte lu dans le ClientHello, si ce paquet en portait un.
    pub domain: Option<String>,
    /// Vrai si le paquet appartient à un flux déjà coupé plus tôt.
    pub already_blocked: bool,
}

impl Decision {
    fn accept() -> Self {
        Self {
            verdict: Verdict::Accept,
            domain: None,
            already_blocked: false,
        }
    }
}

/// Applique la liste noire aux poignées de main TLS qui traversent le tunnel.
pub struct Policy {
    cache: Cache,
    tracker: ClientHelloTracker,
    /// Flux déjà coupés. Sans cette mémoire, le client retransmettrait son
    /// ClientHello et la suite de la connexion passerait : le tracker, lui,
    /// oublie un flux dès qu'il en a tiré un nom.
    blocked: HashSet<FlowKey>,
    /// Consigne les domaines vus dans l'ensemble `seen`.
    record_seen: bool,
}

impl Policy {
    pub fn new(cache: Cache) -> Self {
        Self {
            cache,
            tracker: ClientHelloTracker::new(),
            blocked: HashSet::new(),
            record_seen: true,
        }
    }

    /// N'écrit plus dans l'ensemble `seen` (un aller-retour Redis en moins).
    pub fn without_recording(mut self) -> Self {
        self.record_seen = false;
        self
    }

    /// Nombre de flux actuellement coupés.
    pub fn blocked_flows(&self) -> usize {
        self.blocked.len()
    }

    /// Décide du sort d'un paquet IP brut, tel que NFQUEUE le remet.
    pub fn inspect(&mut self, ip_packet: &[u8]) -> Decision {
        // NFQUEUE remet le paquet IP nu, sans en-tête de liaison.
        let Some(segment) = packet::segment(LinkType::Raw, ip_packet) else {
            return Decision::accept();
        };
        if segment.protocol != Transport::Tcp {
            return Decision::accept();
        }

        let flow = FlowKey::from(&segment);
        // La suite d'un flux déjà condamné : on coupe sans réanalyser.
        if self.blocked.contains(&flow) {
            return Decision {
                verdict: Verdict::Drop,
                domain: None,
                already_blocked: true,
            };
        }

        let Some(domain) = self.tracker.observe(flow, segment.payload) else {
            return Decision::accept();
        };

        let blocked = self.is_blacklisted(&domain);
        if blocked {
            self.remember_blocked(flow);
        } else if self.record_seen {
            // Trace d'observation, sans effet sur la décision.
            let _ = self.cache.add_to_set(SEEN_SET, &domain);
        }

        Decision {
            verdict: if blocked { Verdict::Drop } else { Verdict::Accept },
            domain: Some(domain),
            already_blocked: false,
        }
    }

    /// Consulte la liste noire.
    ///
    /// Redis injoignable : on laisse passer. Couper tout le trafic du tunnel
    /// parce qu'une base de données a redémarré serait pire que le mal.
    fn is_blacklisted(&mut self, domain: &str) -> bool {
        match self.cache.set_contains(BLACKLIST_SET, domain) {
            Ok(found) => found,
            Err(e) => {
                eprintln!("liste noire inaccessible, {domain} laissé passer: {e}");
                false
            }
        }
    }

    fn remember_blocked(&mut self, flow: FlowKey) {
        // Un flux coupé n'est jamais oublié explicitement — le client ne nous
        // dira pas qu'il abandonne. On borne donc, quitte à relâcher un vieux
        // flux : au pire, son ClientHello sera réanalysé et recoupé.
        if self.blocked.len() >= MAX_BLOCKED_FLOWS {
            self.blocked.clear();
        }
        self.blocked.insert(flow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheConfig;
    use crate::sniff::packet::testing::{null_ipv4_tcp, null_ipv4_udp};
    use crate::tls::client_hello::testing::client_hello;

    /// Le paquet IP nu, sans les 4 octets de liaison de la fabrique de test.
    fn ip_packet(frame: Vec<u8>) -> Vec<u8> {
        frame[4..].to_vec()
    }

    /// Rend une politique branchée sur Redis, ou `None` s'il est absent.
    fn policy(namespace: &str) -> Option<Policy> {
        let config = CacheConfig {
            password: test_password(),
            namespace: format!("perses-test:{namespace}"),
            ..CacheConfig::default()
        };
        match Cache::connect(config) {
            Ok(cache) => Some(Policy::new(cache)),
            Err(e) => {
                // Un Redis injoignable alors que le dépôt en déclare un doit
                // faire échouer le test : sinon il passe au vert sans rien
                // vérifier, ce qui est pire que pas de test du tout.
                assert!(
                    test_password().is_none(),
                    "Redis injoignable alors que .env existe ({e}) — \
                     lancer `docker compose up -d redis`"
                );
                eprintln!("test ignoré — pas de .env, Redis non configuré");
                None
            }
        }
    }

    fn test_password() -> Option<String> {
        let env = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/.env")).ok()?;
        env.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "REDIS_PASSWORD").then(|| value.trim().to_string())
        })
    }

    macro_rules! policy_or_skip {
        ($ns:expr) => {
            match policy($ns) {
                Some(policy) => policy,
                None => return,
            }
        };
    }

    #[test]
    fn lets_an_unlisted_domain_through() {
        let mut policy = policy_or_skip!("allow");
        policy.cache.delete(BLACKLIST_SET).ok();

        let packet = ip_packet(null_ipv4_tcp(51000, 443, &client_hello("crates.io")));
        let decision = policy.inspect(&packet);
        assert_eq!(decision.verdict, Verdict::Accept);
        assert_eq!(decision.domain.as_deref(), Some("crates.io"));
    }

    #[test]
    fn cuts_a_blacklisted_domain_and_the_rest_of_its_flow() {
        let mut policy = policy_or_skip!("block");
        policy.cache.delete(BLACKLIST_SET).ok();
        policy.cache.add_to_set(BLACKLIST_SET, "interdit.example").unwrap();

        let hello = ip_packet(null_ipv4_tcp(51001, 443, &client_hello("interdit.example")));
        let decision = policy.inspect(&hello);
        assert_eq!(decision.verdict, Verdict::Drop);
        assert_eq!(decision.domain.as_deref(), Some("interdit.example"));
        assert!(!decision.already_blocked);

        // Retransmission du même ClientHello : coupée sans réanalyse.
        let again = policy.inspect(&hello);
        assert_eq!(again.verdict, Verdict::Drop);
        assert!(again.already_blocked);

        // Suite du flux (données chiffrées) : coupée aussi.
        let data = ip_packet(null_ipv4_tcp(51001, 443, &[0x17, 0x03, 0x03, 0x00, 0x10]));
        assert_eq!(policy.inspect(&data).verdict, Verdict::Drop);

        // Un autre flux vers le même port reste libre.
        let other = ip_packet(null_ipv4_tcp(51002, 443, &client_hello("autorise.example")));
        assert_eq!(policy.inspect(&other).verdict, Verdict::Accept);

        policy.cache.delete(BLACKLIST_SET).ok();
    }

    #[test]
    fn never_holds_back_traffic_it_does_not_understand() {
        let mut policy = policy_or_skip!("passthrough");

        // Ni TCP, ni IP, ni même un paquet complet : tout doit passer.
        for packet in [
            ip_packet(null_ipv4_udp(51000, 53, b"une requete dns")),
            ip_packet(null_ipv4_tcp(51000, 443, b"")),
            vec![0xFF, 0xFF, 0xFF],
            vec![],
        ] {
            assert_eq!(
                policy.inspect(&packet).verdict,
                Verdict::Accept,
                "un paquet non compris ne doit jamais couper le trafic"
            );
        }
    }

    #[test]
    fn blocked_flow_memory_stays_bounded() {
        let mut policy = policy_or_skip!("bounded");
        policy.cache.delete(BLACKLIST_SET).ok();
        policy.cache.add_to_set(BLACKLIST_SET, "interdit.example").unwrap();

        for port in 0..(MAX_BLOCKED_FLOWS as u16).wrapping_add(50) {
            let packet = ip_packet(null_ipv4_tcp(port, 443, &client_hello("interdit.example")));
            policy.inspect(&packet);
        }
        assert!(policy.blocked_flows() <= MAX_BLOCKED_FLOWS);

        policy.cache.delete(BLACKLIST_SET).ok();
    }
}
