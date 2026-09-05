//! Gabarit de module — WireGuard, pas encore branché.
//!
//! Il n'est pas dans le registre de `main.rs` : le démon ne monte pas le
//! tunnel, il l'observe. Le fichier reste comme modèle à copier pour les
//! modules à venir (client UDP vers l'API, lancement de l'API TS) : une
//! structure, un `from_env`, un `impl ContractBase`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::contracts::{ContractBase, ModuleResult};
use crate::starter;

pub struct WireGuard {
    health: Arc<AtomicBool>,
}

impl Default for WireGuard {
    fn default() -> Self {
        Self::from_env()
    }
}

impl WireGuard {
    pub fn from_env() -> Self {
        Self {
            health: starter::health_flag(),
        }
    }

    pub fn cold_start(&self) -> ModuleResult<()> {
        todo!("génération des clés et écriture de la conf — voir crate::wg::cold_start")
    }
}

impl ContractBase for WireGuard {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    fn start(&mut self) -> ModuleResult<()> {
        todo!("montage de l'interface — voir crate::wg::start")
    }

    fn stop(&mut self) -> ModuleResult<()> {
        self.health.store(false, Ordering::Relaxed);
        todo!("descente de l'interface — voir crate::wg::stop")
    }

    fn health(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.health)
    }
}
