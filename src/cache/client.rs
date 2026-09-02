//! Tous les appels à Redis passent par ici.

use std::time::Duration;

use redis::Commands;

use super::config::CacheConfig;
use super::error::{is_disconnect, CacheError, Result};

/// Accès à Redis.
///
/// La connexion est ouverte à la demande et rouverte toute seule si le lien
/// tombe — ce processus est fait pour tourner des jours, et un redémarrage du
/// conteneur Redis ne doit pas l'arrêter.
pub struct Cache {
    client: redis::Client,
    connection: Option<redis::Connection>,
    config: CacheConfig,
}

impl Cache {
    /// Ouvre la connexion et vérifie qu'elle répond.
    pub fn connect(config: CacheConfig) -> Result<Self> {
        let client =
            redis::Client::open(config.connection_info()).map_err(|source| CacheError::Connect {
                endpoint: config.endpoint(),
                source,
            })?;
        let mut cache = Self {
            client,
            connection: None,
            config,
        };
        // Un échec d'authentification ne se voit qu'à la première commande :
        // mieux vaut le découvrir ici qu'au premier domaine capturé.
        cache.ping()?;
        Ok(cache)
    }

    /// Configuration utilisée, mot de passe compris — à ne pas journaliser.
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Vérifie que le serveur répond.
    pub fn ping(&mut self) -> Result<()> {
        self.run("PING", |conn| redis::cmd("PING").query::<()>(conn))
    }

    // ---- clés simples ----

    /// Écrit une valeur, en écrasant l'ancienne.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let key = self.config.key(key);
        self.run("SET", |conn| conn.set(&key, value))
    }

    /// Écrit une valeur qui expirera d'elle-même.
    pub fn set_with_ttl(&mut self, key: &str, value: &str, ttl: Duration) -> Result<()> {
        let key = self.config.key(key);
        let seconds = ttl.as_secs().max(1) as usize;
        self.run("SETEX", |conn| conn.set_ex(&key, value, seconds as u64))
    }

    /// Lit une valeur ; `None` si la clé n'existe pas.
    pub fn get(&mut self, key: &str) -> Result<Option<String>> {
        let key = self.config.key(key);
        self.run("GET", |conn| conn.get(&key))
    }

    /// Supprime une clé, et dit si elle existait.
    pub fn delete(&mut self, key: &str) -> Result<bool> {
        let key = self.config.key(key);
        let removed: i64 = self.run("DEL", |conn| conn.del(&key))?;
        Ok(removed > 0)
    }

    /// Dit si une clé existe.
    pub fn exists(&mut self, key: &str) -> Result<bool> {
        let key = self.config.key(key);
        self.run("EXISTS", |conn| conn.exists(&key))
    }

    /// Incrémente un compteur et rend sa nouvelle valeur.
    ///
    /// La clé est créée à 0 si elle n'existe pas : c'est atomique côté
    /// serveur, contrairement à un `get` suivi d'un `set`.
    pub fn increment(&mut self, key: &str, by: i64) -> Result<i64> {
        let key = self.config.key(key);
        self.run("INCRBY", |conn| conn.incr(&key, by))
    }

    /// Pose une date d'expiration sur une clé existante.
    pub fn expire(&mut self, key: &str, ttl: Duration) -> Result<bool> {
        let key = self.config.key(key);
        let seconds = ttl.as_secs().max(1) as i64;
        self.run("EXPIRE", |conn| conn.expire(&key, seconds))
    }

    // ---- ensembles ----

    /// Ajoute un membre à un ensemble ; rend `true` s'il n'y était pas.
    ///
    /// C'est ce qu'il faut pour une liste de domaines : l'unicité est tenue
    /// par le serveur, sans lire l'ensemble entier.
    pub fn add_to_set(&mut self, set: &str, member: &str) -> Result<bool> {
        let key = self.config.key(set);
        let added: i64 = self.run("SADD", |conn| conn.sadd(&key, member))?;
        Ok(added > 0)
    }

    /// Retire un membre d'un ensemble ; rend `true` s'il y était.
    pub fn remove_from_set(&mut self, set: &str, member: &str) -> Result<bool> {
        let key = self.config.key(set);
        let removed: i64 = self.run("SREM", |conn| conn.srem(&key, member))?;
        Ok(removed > 0)
    }

    /// Dit si un membre appartient à l'ensemble.
    pub fn set_contains(&mut self, set: &str, member: &str) -> Result<bool> {
        let key = self.config.key(set);
        self.run("SISMEMBER", |conn| conn.sismember(&key, member))
    }

    /// Rend tous les membres d'un ensemble.
    pub fn set_members(&mut self, set: &str) -> Result<Vec<String>> {
        let key = self.config.key(set);
        self.run("SMEMBERS", |conn| conn.smembers(&key))
    }

    /// Nombre de membres d'un ensemble, sans les rapatrier.
    pub fn set_len(&mut self, set: &str) -> Result<usize> {
        let key = self.config.key(set);
        self.run("SCARD", |conn| conn.scard(&key))
    }

    // ---- plomberie ----

    /// Exécute une commande, en rouvrant la connexion si le lien a lâché.
    fn run<T>(
        &mut self,
        command: &'static str,
        op: impl Fn(&mut redis::Connection) -> redis::RedisResult<T>,
    ) -> Result<T> {
        match op(self.connection()?) {
            Ok(value) => Ok(value),
            // Lien coupé : Redis a redémarré, ou le réseau a hoqueté. On
            // repart d'une connexion neuve et on retente, une seule fois.
            Err(e) if is_disconnect(&e) => {
                self.connection = None;
                op(self.connection()?).map_err(CacheError::command(command))
            }
            Err(e) => Err(CacheError::command(command)(e)),
        }
    }

    /// Rend la connexion courante, en l'ouvrant si besoin.
    fn connection(&mut self) -> Result<&mut redis::Connection> {
        if self.connection.is_none() {
            let conn = self
                .client
                .get_connection()
                .map_err(|source| CacheError::Connect {
                    endpoint: self.config.endpoint(),
                    source,
                })?;
            self.connection = Some(conn);
        }
        Ok(self
            .connection
            .as_mut()
            .expect("la connexion vient d'être ouverte"))
    }
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("endpoint", &self.config.endpoint())
            .field("connected", &self.connection.is_some())
            .finish()
    }
}
