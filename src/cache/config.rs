//! Où joindre Redis, et sous quel préfixe de clés.

use super::error::{CacheError, Result};

/// Hôte par défaut : le conteneur du `compose.yaml` n'écoute qu'en local.
pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 6379;
/// Préfixe appliqué à toutes les clés, pour cohabiter avec d'autres usages
/// de la même instance.
pub const DEFAULT_NAMESPACE: &str = "perses";

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub host: String,
    pub port: u16,
    /// Mot de passe `requirepass`, jamais journalisé.
    pub password: Option<String>,
    pub db: i64,
    pub namespace: String,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            password: None,
            db: 0,
            namespace: DEFAULT_NAMESPACE.to_string(),
        }
    }
}

impl CacheConfig {
    /// Lit `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_DB`.
    ///
    /// C'est le pendant du `.env` utilisé par `compose.yaml`.
    pub fn from_env() -> Result<Self> {
        let mut cfg = Self::default();
        if let Ok(host) = std::env::var("REDIS_HOST") {
            cfg.host = host;
        }
        if let Ok(port) = std::env::var("REDIS_PORT") {
            cfg.port = port
                .parse()
                .map_err(|_| CacheError::InvalidConfig(format!("REDIS_PORT invalide: {port}")))?;
        }
        if let Ok(db) = std::env::var("REDIS_DB") {
            cfg.db = db
                .parse()
                .map_err(|_| CacheError::InvalidConfig(format!("REDIS_DB invalide: {db}")))?;
        }
        // Une variable vide vaut « pas de mot de passe ».
        cfg.password = std::env::var("REDIS_PASSWORD").ok().filter(|p| !p.is_empty());
        Ok(cfg)
    }

    /// Adresse lisible, sans le mot de passe.
    pub fn endpoint(&self) -> String {
        format!("{}:{}/{}", self.host, self.port, self.db)
    }

    /// Traduit la configuration pour la bibliothèque cliente.
    ///
    /// On construit l'objet de connexion plutôt qu'une URL `redis://…` : un
    /// mot de passe issu de `openssl rand -base64` contient des `/`, `+` et
    /// `=` qu'il faudrait sinon encoder à la main.
    pub(crate) fn connection_info(&self) -> redis::ConnectionInfo {
        redis::ConnectionInfo {
            addr: redis::ConnectionAddr::Tcp(self.host.clone(), self.port),
            redis: redis::RedisConnectionInfo {
                db: self.db,
                username: None,
                password: self.password.clone(),
                ..Default::default()
            },
        }
    }

    /// Préfixe une clé applicative : `visited` → `perses:visited`.
    pub fn key(&self, key: &str) -> String {
        if self.namespace.is_empty() {
            key.to_string()
        } else {
            format!("{}:{}", self.namespace, key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_keys() {
        let cfg = CacheConfig::default();
        assert_eq!(cfg.key("visited"), "perses:visited");

        let flat = CacheConfig {
            namespace: String::new(),
            ..Default::default()
        };
        assert_eq!(flat.key("visited"), "visited");
    }

    #[test]
    fn endpoint_never_shows_the_password() {
        let cfg = CacheConfig {
            password: Some("secret-du-vps".to_string()),
            ..Default::default()
        };
        assert_eq!(cfg.endpoint(), "127.0.0.1:6379/0");
        assert!(!cfg.endpoint().contains("secret"));
    }

    #[test]
    fn connection_info_carries_the_credentials() {
        let cfg = CacheConfig {
            host: "10.8.0.1".to_string(),
            port: 6380,
            password: Some("s3cr3t".to_string()),
            db: 3,
            ..Default::default()
        };
        let info = cfg.connection_info();
        assert_eq!(info.redis.password.as_deref(), Some("s3cr3t"));
        assert_eq!(info.redis.db, 3);
    }
}
