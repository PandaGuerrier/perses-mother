//! Le sniffer vu comme un module du démon.
//!
//! Emballage mince autour de [`capture::sniff`] : il résout l'interface, ouvre
//! sa connexion Redis, et cède la main à la boucle de capture.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::cache::{Cache, CacheConfig};
use crate::contracts::{ContractBase, ModuleResult};
use crate::starter;
use crate::wg;

use super::capture::{self, SniffConfig, DEFAULT_FILTER};

/// Capture passive du trafic du tunnel.
pub struct Sniffer {
    /// Périphérique imposé par `PERSES_DEVICE`, s'il l'est.
    device: Option<String>,
    /// Interface WireGuard à résoudre sinon (`PERSES_INTERFACE`).
    interface: String,
    /// Filtre BPF (`PERSES_BPF_FILTER`).
    filter: String,
    health: Arc<AtomicBool>,
}

impl Sniffer {
    /// Lit `PERSES_DEVICE`, `PERSES_INTERFACE`, `PERSES_BPF_FILTER`.
    ///
    /// Ne résout rien et n'ouvre rien : tout ce qui peut échouer attend
    /// [`ContractBase::start`], sous la surveillance du starter.
    pub fn from_env() -> Self {
        Self {
            device: env_var("PERSES_DEVICE"),
            interface: env_var("PERSES_INTERFACE")
                .unwrap_or_else(|| wg::DEFAULT_INTERFACE.to_string()),
            filter: env_var("PERSES_BPF_FILTER").unwrap_or_else(|| DEFAULT_FILTER.to_string()),
            health: starter::health_flag(),
        }
    }

    /// Nom du périphérique que libpcap attend.
    ///
    /// Sous macOS, l'interface logique `wg0` est un `utunN` : c'est
    /// [`wg::resolve_device`] qui connaît la correspondance.
    fn device(&self) -> ModuleResult<String> {
        if let Some(device) = &self.device {
            return Ok(device.clone());
        }
        let resolved = wg::resolve_device(&self.interface)?;
        resolved.ok_or_else(|| {
            format!(
                "interface {} arrêtée — la monter, ou imposer PERSES_DEVICE",
                self.interface
            )
            .into()
        })
    }
}

impl ContractBase for Sniffer {
    fn name(&self) -> &'static str {
        "sniffer"
    }

    fn start(&mut self) -> ModuleResult<()> {
        let mut cfg = SniffConfig::new(self.device()?);
        cfg.filter = self.filter.clone();
        // Une connexion Redis par module : `Cache` n'est ni `Clone` ni `Sync`,
        // et chaque module vit dans son thread.
        let cache = Cache::connect(CacheConfig::from_env()?)?;

        self.health.store(true, Ordering::Relaxed);
        let outcome = capture::sniff(&cfg, cache);
        self.health.store(false, Ordering::Relaxed);

        match outcome {
            // `sniff` renvoie `Infallible` en cas de succès : ce bras n'a
            // aucune valeur possible.
            Ok(never) => match never {},
            Err(err) => Err(err.into()),
        }
    }

    fn stop(&mut self) -> ModuleResult<()> {
        // La boucle pcap n'a pas de point d'annulation : baisser le drapeau
        // est tout ce qu'on peut faire tant qu'aucun gestionnaire de signal
        // n'est câblé. Le thread meurt avec le processus.
        self.health.store(false, Ordering::Relaxed);
        Ok(())
    }

    fn health(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.health)
    }
}

/// Variable d'environnement non vide, ou `None` — une variable vide vaut
/// « pas de valeur », comme dans [`CacheConfig::from_env`].
fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}
