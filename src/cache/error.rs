use std::fmt;

pub type Result<T> = std::result::Result<T, CacheError>;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("connexion à {endpoint} impossible: {source}")]
    Connect {
        endpoint: String,
        #[source]
        source: redis::RedisError,
    },
    #[error("commande {command} échouée: {source}")]
    Command {
        command: &'static str,
        #[source]
        source: redis::RedisError,
    },
    #[error("configuration invalide: {0}")]
    InvalidConfig(String),
}

impl CacheError {
    pub(crate) fn command(command: &'static str) -> impl Fn(redis::RedisError) -> Self {
        move |source| CacheError::Command { command, source }
    }

    /// Vrai si l'erreur vient du lien réseau plutôt que de la commande.
    pub fn is_connection_issue(&self) -> bool {
        match self {
            CacheError::Connect { .. } => true,
            CacheError::Command { source, .. } => is_disconnect(source),
            CacheError::InvalidConfig(_) => false,
        }
    }
}

/// Une erreur qui justifie de rouvrir la connexion.
pub(crate) fn is_disconnect(error: &redis::RedisError) -> bool {
    error.is_connection_dropped() || error.is_io_error() || error.is_connection_refusal()
}

/// Masque un mot de passe dans un message d'erreur.
pub(crate) struct Redacted<'a>(pub &'a str);

impl fmt::Display for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
