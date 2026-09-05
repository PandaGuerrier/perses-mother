//! Le filtrage de la liste noire vu comme un module du démon.
//!
//! Emballage mince autour de [`queue::filter`] : il ouvre sa connexion Redis,
//! construit la [`Policy`], et cède la main à la boucle NFQUEUE.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::cache::{Cache, CacheConfig};
use crate::contracts::{ContractBase, ModuleResult};
use crate::starter;
use crate::wg;

use super::policy::Policy;
use super::queue::{self, FilterConfig};

/// Coupe les connexions vers les domaines de la liste noire.
pub struct Blacklist {
    cfg: FilterConfig,
    /// Interface citée dans la règle `iptables` rappelée au démarrage.
    interface: String,
    health: Arc<AtomicBool>,
}

impl Blacklist {
    /// Lit `PERSES_QUEUE` et `PERSES_INTERFACE`.
    ///
    /// Un `PERSES_QUEUE` illisible n'est pas une erreur fatale : on retombe
    /// sur la file par défaut plutôt que d'empêcher le démon de démarrer.
    pub fn from_env() -> Self {
        let mut cfg = FilterConfig::default();
        if let Some(queue) = env_var("PERSES_QUEUE") {
            match queue.parse() {
                Ok(queue) => cfg.queue = queue,
                Err(_) => eprintln!("[blacklist] PERSES_QUEUE invalide: {queue} — file {} retenue", cfg.queue),
            }
        }
        Self {
            cfg,
            interface: env_var("PERSES_INTERFACE")
                .unwrap_or_else(|| wg::DEFAULT_INTERFACE.to_string()),
            health: starter::health_flag(),
        }
    }
}

impl ContractBase for Blacklist {
    fn name(&self) -> &'static str {
        "blacklist"
    }

    fn start(&mut self) -> ModuleResult<()> {
        let policy = Policy::new(Cache::connect(CacheConfig::from_env()?)?);

        // Le module ne pose pas la règle lui-même : toucher au pare-feu d'un
        // serveur en production est la décision de son administrateur.
        eprintln!(
            "[blacklist] règle à poser si ce n'est pas déjà fait :\n  {}",
            queue::iptables_rule(self.cfg.queue, &self.interface)
        );

        self.health.store(true, Ordering::Relaxed);
        let outcome = queue::filter(&self.cfg, policy);
        self.health.store(false, Ordering::Relaxed);

        match outcome {
            // `filter` renvoie `Infallible` en cas de succès.
            Ok(never) => match never {},
            Err(err) => Err(err.into()),
        }
    }

    fn stop(&mut self) -> ModuleResult<()> {
        // `Queue::recv` bloque sans délai : rien à interrompre proprement tant
        // qu'aucun gestionnaire de signal n'est câblé.
        self.health.store(false, Ordering::Relaxed);
        Ok(())
    }

    fn health(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.health)
    }
}

/// Variable d'environnement non vide, ou `None`.
fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}
