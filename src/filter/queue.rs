//! Boucle NFQUEUE : le noyau nous soumet les paquets, on rend un verdict.
//!
//! Contrairement à la capture de [`crate::sniff`], qui observe des copies,
//! le paquet est ici *retenu* dans le noyau tant qu'on n'a pas répondu. C'est
//! ce qui permet de couper une connexion avant que son ClientHello ne parte,
//! sans course entre l'observation et le blocage.
//!
//! La règle qui alimente la file doit être posée à part :
//!
//! ```sh
//! iptables -I FORWARD -i wg0 -p tcp --dport 443 -j NFQUEUE --queue-num 0
//! ```

use std::convert::Infallible;
use std::io;

use super::policy::Policy;

/// Numéro de file par défaut, à accorder avec `--queue-num`.
pub const DEFAULT_QUEUE: u16 = 0;

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("file NFQUEUE {queue} inaccessible: {source} (root requis)")]
    Open {
        queue: u16,
        #[source]
        source: io::Error,
    },
    #[error("file NFQUEUE interrompue: {0}")]
    Queue(#[source] io::Error),
}

/// Réglages de la boucle de filtrage.
#[derive(Debug, Clone)]
pub struct FilterConfig {
    /// Numéro de la file, identique à celui de la règle `iptables`.
    pub queue: u16,
    /// Écrit une ligne par domaine décidé sur stdout.
    pub verbose: bool,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            queue: DEFAULT_QUEUE,
            verbose: true,
        }
    }
}

/// Commande à poser pour alimenter la file.
pub fn iptables_rule(queue: u16, interface: &str) -> String {
    format!("iptables -I FORWARD -i {interface} -p tcp --dport 443 -j NFQUEUE --queue-num {queue}")
}

/// Traite la file jusqu'à erreur fatale.
///
/// Le type de succès est [`Infallible`] : cette boucle ne s'arrête pas d'elle-même.
#[cfg(target_os = "linux")]
pub fn filter(cfg: &FilterConfig, mut policy: Policy) -> Result<Infallible, FilterError> {
    use super::policy::Verdict;
    use std::io::Write as _;

    let mut queue = nfq::Queue::open().map_err(|source| FilterError::Open {
        queue: cfg.queue,
        source,
    })?;
    queue
        .bind(cfg.queue)
        .map_err(|source| FilterError::Open {
            queue: cfg.queue,
            source,
        })?;

    eprintln!("filtrage de la file NFQUEUE {}", cfg.queue);

    loop {
        let mut msg = queue.recv().map_err(FilterError::Queue)?;
        let decision = policy.inspect(msg.get_payload());

        msg.set_verdict(match decision.verdict {
            Verdict::Accept => nfq::Verdict::Accept,
            Verdict::Drop => nfq::Verdict::Drop,
        });
        // Le paquet reste bloqué dans le noyau tant que le verdict n'est pas
        // renvoyé : ne jamais sortir de la boucle sans répondre.
        queue.verdict(msg).map_err(FilterError::Queue)?;

        if cfg.verbose {
            if let Some(domain) = decision.domain {
                let verb = match decision.verdict {
                    Verdict::Drop => "BLOQUÉ",
                    Verdict::Accept => "permis",
                };
                let stdout = io::stdout();
                let mut out = stdout.lock();
                if writeln!(out, "{verb} {domain}").is_ok() {
                    let _ = out.flush();
                }
            }
        }
    }
}

/// NFQUEUE est une interface du noyau Linux : ailleurs, la commande refuse
/// de démarrer plutôt que de laisser croire qu'elle filtre.
#[cfg(not(target_os = "linux"))]
pub fn filter(_cfg: &FilterConfig, _policy: Policy) -> Result<Infallible, FilterError> {
    Err(FilterError::Open {
        queue: 0,
        source: io::Error::new(
            io::ErrorKind::Unsupported,
            "NFQUEUE n'existe que sous Linux",
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_printed_rule_matches_the_queue_it_serves() {
        let rule = iptables_rule(3, "wg0");
        assert!(rule.contains("--queue-num 3"));
        assert!(rule.contains("-i wg0"));
    }
}
