use std::io;
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, WgError>;

#[derive(Debug, thiserror::Error)]
pub enum WgError {
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("`{0}` introuvable dans le PATH (paquet wireguard-tools manquant ?)")]
    MissingBinary(&'static str),

    #[error("`{cmd}` a échoué (code {code}): {stderr}")]
    CommandFailed {
        cmd: String,
        code: i32,
        stderr: String,
    },

    #[error("clé wireguard invalide: {0}")]
    InvalidKey(String),

    #[error("configuration absente: {0} — lancer `cold-start` d'abord")]
    NotProvisioned(PathBuf),

    #[error("configuration déjà présente: {0} — utiliser `--force` pour la régénérer")]
    AlreadyProvisioned(PathBuf),

    #[error("configuration invalide: {0}")]
    InvalidConfig(String),

    #[error("droits insuffisants — {0} ; relancer avec sudo")]
    PermissionDenied(String),
}

impl WgError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        WgError::Io {
            path: path.into(),
            source,
        }
    }
}
