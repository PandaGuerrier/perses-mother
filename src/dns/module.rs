//! Le relais DNS vu comme un module du démon.
//!
//! Emballage mince autour de [`server::serve`] : il trouve l'adresse du
//! tunnel, ouvre sa connexion Redis, construit la [`Policy`], et cède la main
//! à la boucle d'écoute.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::cache::{Cache, CacheConfig};
use crate::contracts::{ContractBase, ModuleResult};
use crate::starter;
use crate::wg;

use super::policy::Policy;
use super::server::{self, DnsConfig, DEFAULT_QUEUE, DEFAULT_TIMEOUT, DEFAULT_WORKERS, DNS_PORT};

/// Sert le DNS des clients du tunnel, et nie les noms marqués.
pub struct Resolver {
    /// Adresse d'écoute imposée par `PERSES_DNS_BIND`, si elle l'est.
    bind: Option<String>,
    /// Interface WireGuard dont on prend l'adresse sinon (`PERSES_INTERFACE`).
    interface: String,
    /// Résolveur amont (`PERSES_DNS_UPSTREAM`).
    upstream: String,
    timeout: Duration,
    workers: usize,
    queue: usize,
    health: Arc<AtomicBool>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Resolver {
    /// Lit `PERSES_DNS_BIND`, `PERSES_INTERFACE`, `PERSES_DNS_UPSTREAM`,
    /// `PERSES_DNS_TIMEOUT`, `PERSES_DNS_WORKERS`, `PERSES_DNS_QUEUE`.
    ///
    /// Ne résout rien et n'ouvre rien : tout ce qui peut échouer attend
    /// [`ContractBase::start`], sous la surveillance du starter.
    pub fn from_env() -> Self {
        Self {
            bind: env_var("PERSES_DNS_BIND"),
            interface: env_var("PERSES_INTERFACE")
                .unwrap_or_else(|| wg::DEFAULT_INTERFACE.to_string()),
            upstream: env_var("PERSES_DNS_UPSTREAM")
                .unwrap_or_else(|| server::DEFAULT_UPSTREAM.to_string()),
            timeout: number("PERSES_DNS_TIMEOUT")
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_TIMEOUT),
            workers: number("PERSES_DNS_WORKERS").unwrap_or(DEFAULT_WORKERS as u64) as usize,
            queue: number("PERSES_DNS_QUEUE").unwrap_or(DEFAULT_QUEUE as u64) as usize,
            health: starter::health_flag(),
        }
    }

    /// Adresse sur laquelle écouter.
    ///
    /// Sans `PERSES_DNS_BIND`, c'est celle que porte l'interface du tunnel :
    /// écouter sur `0.0.0.0` exposerait un résolveur ouvert sur l'Internet,
    /// alors que ce service n'est destiné qu'aux pairs.
    fn listen_address(&self) -> ModuleResult<SocketAddr> {
        if let Some(bind) = &self.bind {
            return Ok(parse_bind(bind)?);
        }

        let device = wg::resolve_device(&self.interface)?.ok_or_else(|| {
            format!(
                "interface {} arrêtée — la monter, ou imposer PERSES_DNS_BIND",
                self.interface
            )
        })?;
        let address = wg::interface_address(&device)?.ok_or_else(|| {
            format!(
                "aucune adresse sur {device} — imposer PERSES_DNS_BIND (ex. 10.8.0.1:{DNS_PORT})"
            )
        })?;
        Ok(SocketAddr::new(address, DNS_PORT))
    }
}

impl ContractBase for Resolver {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn start(&mut self) -> ModuleResult<()> {
        let mut cfg = DnsConfig::new(self.listen_address()?);
        cfg.upstream = parse_bind(&self.upstream)?;
        cfg.timeout = self.timeout;
        cfg.workers = self.workers;
        cfg.queue = self.queue;

        // Une connexion Redis par module : `Cache` n'est ni `Clone` ni `Sync`,
        // et chaque module vit dans son thread.
        let policy = Policy::new(Cache::connect(CacheConfig::from_env()?)?);

        eprintln!(
            "[dns] les clients doivent interroger {} — le pousser aux pairs \
             (`DNS = {}` dans leur configuration)",
            cfg.bind,
            cfg.bind.ip()
        );

        self.health.store(true, Ordering::Relaxed);
        let outcome = server::serve(&cfg, policy);
        self.health.store(false, Ordering::Relaxed);

        match outcome {
            // `serve` renvoie `Infallible` en cas de succès : ce bras n'a
            // aucune valeur possible.
            Ok(never) => match never {},
            Err(err) => Err(err.into()),
        }
    }

    fn stop(&mut self) -> ModuleResult<()> {
        // `recv_from` bloque sans délai : baisser le drapeau est tout ce
        // qu'on peut faire tant qu'aucun gestionnaire de signal n'est câblé.
        self.health.store(false, Ordering::Relaxed);
        Ok(())
    }

    fn health(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.health)
    }
}

/// Lit une adresse écrite `ip:port` ou `ip` — le port 53 étant sous-entendu.
fn parse_bind(value: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DNS_PORT));
    }
    Err(format!(
        "adresse illisible: {value} — attendu `10.8.0.1` ou `10.8.0.1:{DNS_PORT}`"
    ))
}

/// Variable d'environnement non vide, ou `None` — une variable vide vaut
/// « pas de valeur », comme dans [`CacheConfig::from_env`].
fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Entier strictement positif lu dans l'environnement.
///
/// Une valeur illisible n'est pas une erreur fatale : on retombe sur le
/// défaut plutôt que d'empêcher le démon de démarrer, comme le fait
/// [`crate::filter::Blacklist::from_env`] pour `PERSES_QUEUE`.
fn number(key: &str) -> Option<u64> {
    let raw = env_var(key)?;
    match raw.trim().parse() {
        Ok(n) if n > 0 => Some(n),
        _ => {
            eprintln!("[dns] {key} invalide: {raw} — valeur par défaut retenue");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_without_a_port_is_served_on_53() {
        assert_eq!(
            parse_bind("10.8.0.1").unwrap(),
            "10.8.0.1:53".parse().unwrap()
        );
        assert_eq!(
            parse_bind("10.8.0.1:5353").unwrap(),
            "10.8.0.1:5353".parse().unwrap()
        );
        assert_eq!(parse_bind("::1").unwrap(), "[::1]:53".parse().unwrap());
    }

    #[test]
    fn an_unreadable_address_says_what_was_expected() {
        let err = parse_bind("wg0").unwrap_err();
        assert!(err.contains("10.8.0.1"), "{err}");
    }
}
