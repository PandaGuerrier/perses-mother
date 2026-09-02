//! Tests du module `cache` contre un vrai serveur Redis.
//!
//! Lancer le serveur avec `docker compose up -d redis` ; sans lui, ces tests
//! s'annoncent ignorés plutôt que d'échouer.

use std::time::Duration;

use perses_mother::cache::{Cache, CacheConfig};

/// Lit le `.env` du dépôt, que `compose.yaml` utilise aussi.
fn env_file_password() -> Option<String> {
    let content = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/.env")).ok()?;
    content.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "REDIS_PASSWORD").then(|| value.trim().to_string())
    })
}

/// Ouvre une connexion, ou rend `None` si Redis n'est pas joignable.
fn cache(namespace: &str) -> Option<Cache> {
    let config = CacheConfig {
        password: env_file_password(),
        namespace: format!("perses-test:{namespace}"),
        ..CacheConfig::default()
    };
    match Cache::connect(config) {
        Ok(cache) => Some(cache),
        Err(e) => {
            eprintln!("test ignoré — Redis injoignable ({e})");
            None
        }
    }
}

macro_rules! cache_or_skip {
    ($namespace:expr) => {
        match cache($namespace) {
            Some(cache) => cache,
            None => return,
        }
    };
}

#[test]
fn stores_and_reads_back_a_value() {
    let mut cache = cache_or_skip!("kv");
    cache.delete("greeting").unwrap();

    assert_eq!(cache.get("greeting").unwrap(), None, "clé absente au départ");
    cache.set("greeting", "bonjour").unwrap();
    assert_eq!(cache.get("greeting").unwrap().as_deref(), Some("bonjour"));
    assert!(cache.exists("greeting").unwrap());

    cache.set("greeting", "rebonjour").unwrap();
    assert_eq!(cache.get("greeting").unwrap().as_deref(), Some("rebonjour"));

    assert!(cache.delete("greeting").unwrap(), "la clé existait");
    assert!(!cache.delete("greeting").unwrap(), "elle a déjà disparu");
    assert_eq!(cache.get("greeting").unwrap(), None);
}

#[test]
fn counts_atomically() {
    let mut cache = cache_or_skip!("counter");
    cache.delete("hits").unwrap();

    assert_eq!(cache.increment("hits", 1).unwrap(), 1, "créée à 0 puis +1");
    assert_eq!(cache.increment("hits", 1).unwrap(), 2);
    assert_eq!(cache.increment("hits", 10).unwrap(), 12);
    assert_eq!(cache.get("hits").unwrap().as_deref(), Some("12"));

    cache.delete("hits").unwrap();
}

#[test]
fn a_value_with_a_ttl_expires_on_its_own() {
    let mut cache = cache_or_skip!("ttl");
    cache.delete("fugace").unwrap();

    cache
        .set_with_ttl("fugace", "valeur", Duration::from_secs(1))
        .unwrap();
    assert!(cache.exists("fugace").unwrap());

    std::thread::sleep(Duration::from_millis(1500));
    assert!(!cache.exists("fugace").unwrap(), "la clé a expiré");
}

#[test]
fn a_set_keeps_each_member_once() {
    let mut cache = cache_or_skip!("set");
    cache.delete("visited").unwrap();

    assert!(cache.add_to_set("visited", "github.com").unwrap(), "nouveau");
    assert!(
        !cache.add_to_set("visited", "github.com").unwrap(),
        "déjà connu"
    );
    cache.add_to_set("visited", "crates.io").unwrap();

    assert_eq!(cache.set_len("visited").unwrap(), 2);
    assert!(cache.set_contains("visited", "crates.io").unwrap());
    assert!(!cache.set_contains("visited", "example.com").unwrap());

    let mut members = cache.set_members("visited").unwrap();
    members.sort();
    assert_eq!(members, vec!["crates.io", "github.com"]);

    assert!(cache.remove_from_set("visited", "crates.io").unwrap());
    assert_eq!(cache.set_len("visited").unwrap(), 1);

    cache.delete("visited").unwrap();
}

#[test]
fn keys_are_namespaced() {
    let mut first = cache_or_skip!("namespace");
    first.set("marqueur", "1").unwrap();

    // La clé réelle porte le préfixe : deux instances de `Cache` avec des
    // espaces différents ne se marchent pas dessus.
    assert_eq!(first.config().key("marqueur"), "perses-test:namespace:marqueur");

    let mut other = match cache("autre-namespace") {
        Some(cache) => cache,
        None => return,
    };
    assert_eq!(other.get("marqueur").unwrap(), None);

    first.delete("marqueur").unwrap();
}

#[test]
fn a_wrong_password_is_reported_as_a_connection_problem() {
    if env_file_password().is_none() {
        eprintln!("test ignoré — pas de .env");
        return;
    }
    let config = CacheConfig {
        password: Some("mauvais-mot-de-passe".to_string()),
        ..CacheConfig::default()
    };
    match Cache::connect(config) {
        Err(e) => assert!(
            !e.to_string().contains("mauvais-mot-de-passe"),
            "le mot de passe ne doit pas fuiter dans l'erreur: {e}"
        ),
        Ok(_) => eprintln!("test ignoré — Redis accepte les connexions sans mot de passe"),
    }
}

/// Redémarre le conteneur : à lancer explicitement avec
/// `cargo test --test cache_redis -- --ignored survives`.
#[test]
#[ignore = "redémarre le conteneur Redis"]
fn survives_a_server_restart() {
    let mut cache = cache_or_skip!("restart");
    cache.set("avant", "coupure").unwrap();

    let restarted = std::process::Command::new("docker-compose")
        .args(["restart", "redis"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status();
    if !matches!(restarted, Ok(status) if status.success()) {
        eprintln!("test ignoré — docker-compose indisponible");
        return;
    }
    // Le conteneur met un instant à réaccepter les connexions.
    std::thread::sleep(Duration::from_secs(2));

    // La connexion du client est morte : la commande doit la rouvrir seule.
    assert_eq!(
        cache.get("avant").unwrap().as_deref(),
        Some("coupure"),
        "la valeur a survécu au redémarrage grâce au volume"
    );
    cache.set("apres", "reprise").unwrap();
    assert_eq!(cache.get("apres").unwrap().as_deref(), Some("reprise"));

    cache.delete("avant").unwrap();
    cache.delete("apres").unwrap();
}
