//! Où déposer les rapports, et à quel rythme.

use std::path::PathBuf;
use std::time::Duration;

/// Fichier où les rapports sont écrits, une ligne par observation.
pub const DEFAULT_SOCKET: &str = "/tmp/perses.socket";
/// Rapports en attente d'écriture tolérés avant d'en jeter.
pub const DEFAULT_QUEUE: usize = 256;
/// Durée pendant laquelle l'état des pairs est réutilisé sans le relire.
pub const DEFAULT_PEERS_TTL: Duration = Duration::from_secs(5);

/// Réglages du rapporteur, tous issus de l'environnement.
#[derive(Debug, Clone)]
pub struct ReportConfig {
    /// Fichier de sortie (`PERSES_SOCKET`).
    pub socket: PathBuf,
    /// Taille de la file entre la capture et l'écriture.
    pub queue: usize,
    /// Fraîcheur exigée de `wg show … dump` (`PERSES_PEERS_TTL`, en secondes).
    pub peers_ttl: Duration,
}

impl ReportConfig {
    /// Lit l'environnement, en retombant sur les valeurs par défaut.
    ///
    /// Rien n'est obligatoire : sans configuration, les rapports partent dans
    /// [`DEFAULT_SOCKET`].
    pub fn from_env() -> Self {
        Self {
            socket: env_var("PERSES_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET)),
            queue: env_var("PERSES_REPORT_QUEUE")
                .and_then(|v| v.parse().ok())
                .filter(|&n| n > 0)
                .unwrap_or(DEFAULT_QUEUE),
            peers_ttl: duration("PERSES_PEERS_TTL").unwrap_or(DEFAULT_PEERS_TTL),
        }
    }
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            socket: PathBuf::from(DEFAULT_SOCKET),
            queue: DEFAULT_QUEUE,
            peers_ttl: DEFAULT_PEERS_TTL,
        }
    }
}

/// Variable d'environnement non vide, ou `None` — une variable vide vaut
/// « pas de valeur », comme dans [`crate::cache::CacheConfig::from_env`].
fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn duration(key: &str) -> Option<Duration> {
    env_var(key)
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falls_back_on_the_default_socket() {
        assert_eq!(
            ReportConfig::default().socket,
            PathBuf::from("/tmp/perses.socket")
        );
    }

    #[test]
    fn the_default_queue_is_bounded() {
        assert_eq!(ReportConfig::default().queue, DEFAULT_QUEUE);
        assert!(DEFAULT_QUEUE > 0);
    }
}
