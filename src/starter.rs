//! Le starter — la seule chose que `main` sait faire.
//!
//! Il reçoit la liste des modules, en lance un par thread, et attend. Il ne
//! connaît ni la capture ni le filtrage : ajouter un module ne le modifie pas.
//!
//! ```no_run
//! use perses_mother::contracts::ContractBase;
//! use perses_mother::sniff::Sniffer;
//! use perses_mother::starter;
//!
//! let modules: Vec<Box<dyn ContractBase>> = vec![Box::new(Sniffer::from_env())];
//! starter::run(modules);
//! ```
//!
//! Un module qui échoue est journalisé, les autres continuent. C'est ce qui
//! permet de lancer le démon sur macOS, où le filtrage NFQUEUE est impossible,
//! sans perdre la capture.

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crate::contracts::ContractBase;

/// Lance tous les modules et attend qu'ils s'arrêtent.
///
/// Ne rend la main que lorsque le dernier thread est terminé — en pratique,
/// jamais : les boucles des modules tournent jusqu'à Ctrl-C. Le code de sortie
/// n'est `FAILURE` que si *aucun* module n'a survécu.
pub fn run(modules: Vec<Box<dyn ContractBase>>) -> ExitCode {
    if modules.is_empty() {
        eprintln!("[starter] aucun module à lancer");
        return ExitCode::FAILURE;
    }

    let total = modules.len();
    let mut running = Vec::with_capacity(total);

    for mut module in modules {
        let name = module.name();
        // Le clone est pris avant que le module ne parte dans son thread :
        // après le `move`, c'est le seul lien qui reste avec lui.
        let health = module.health();

        let spawned = thread::Builder::new()
            .name(name.to_string())
            .spawn(move || match module.start() {
                Ok(()) => {
                    eprintln!("[{name}] terminé");
                    true
                }
                Err(err) => {
                    eprintln!("[{name}] arrêté: {err}");
                    false
                }
            });

        match spawned {
            Ok(handle) => running.push((name, health, handle)),
            Err(err) => eprintln!("[{name}] thread impossible à créer: {err}"),
        }
    }

    let mut alive = 0usize;
    for (name, health, handle) in running {
        let ok = match handle.join() {
            Ok(ok) => ok,
            Err(_) => {
                // Un panic saute le `store(false)` du module : on le corrige
                // ici, pour qu'aucun drapeau ne reste levé sur un mort.
                eprintln!("[{name}] panic");
                health.store(false, Ordering::Relaxed);
                false
            }
        };
        if ok {
            alive += 1;
        }
    }

    if alive == 0 {
        eprintln!("[starter] les {total} module(s) se sont arrêtés en erreur");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Drapeau de santé neuf, baissé.
///
/// Raccourci pour les modules, qui en tiennent tous un.
pub fn health_flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}
