//! Cycle de vie du serveur WireGuard : provisionnement puis démarrage.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use super::config::{self, ServerConfig};
use super::error::{Result, WgError};
use super::keys::KeyPair;

const WG_QUICK: &str = "wg-quick";
const WG: &str = "wg";
/// Répertoire où `wg-quick` note la correspondance interface → périphérique.
const RUN_DIR: &str = "/var/run/wireguard";

/// Résultat d'un `cold_start`.
#[derive(Debug)]
pub struct Provisioning {
    /// Clé publique du serveur, à distribuer aux clients.
    pub public_key: String,
    /// Chemin du fichier de configuration écrit.
    pub config_path: std::path::PathBuf,
    /// `false` si la configuration existait déjà et a été réutilisée.
    pub created: bool,
}

/// État d'une interface après un appel à [`start`].
#[derive(Debug, PartialEq, Eq)]
pub enum StartOutcome {
    /// L'interface a été montée par cet appel.
    Started {
        /// Périphérique réel créé (`wg0` sous Linux, `utunN` sous macOS).
        device: String,
    },
    /// L'interface tournait déjà : rien n'a été fait.
    AlreadyRunning {
        /// Périphérique réel déjà en place.
        device: String,
    },
}

/// État d'une interface après un appel à [`stop`].
#[derive(Debug, PartialEq, Eq)]
pub enum StopOutcome {
    /// L'interface a été descendue par cet appel.
    Stopped,
    /// L'interface ne tournait pas : rien n'a été fait.
    AlreadyStopped,
}

/// Instantané d'une interface active.
#[derive(Debug)]
pub struct Status {
    /// Périphérique réel interrogé (`wg0` sous Linux, `utunN` sous macOS).
    pub device: String,
    /// Sortie brute de `wg show <device>`.
    pub details: String,
}

/// Provisionne le serveur : paire de clés + fichier `wg-quick`.
///
/// Idempotent par défaut — si la configuration existe déjà, elle est relue et
/// sa clé publique renvoyée. Avec `force`, les clés sont régénérées et les
/// fichiers réécrits, ce qui invalide tous les pairs déjà distribués.
pub fn cold_start(cfg: &ServerConfig, force: bool) -> Result<Provisioning> {
    cfg.validate()?;
    let config_path = cfg.config_path();

    if config_path.exists() && !force {
        return reuse_existing(&config_path);
    }

    ensure_config_dir(&cfg.config_dir)?;
    let keypair = KeyPair::generate();
    let rendered = cfg.render(&keypair.private_b64())?;

    write_secret(&cfg.private_key_path(), &format!("{}\n", keypair.private_b64()))?;
    write_public(&cfg.public_key_path(), &format!("{}\n", keypair.public_b64()))?;
    write_secret(&config_path, &rendered)?;

    Ok(Provisioning {
        public_key: keypair.public_b64(),
        config_path,
        created: true,
    })
}

/// Monte l'interface via `wg-quick up`.
///
/// Renvoie [`StartOutcome::AlreadyRunning`] si l'interface est déjà active, et
/// [`WgError::NotProvisioned`] si `cold_start` n'a pas encore été exécuté.
pub fn start(cfg: &ServerConfig) -> Result<StartOutcome> {
    cfg.validate()?;
    let config_path = cfg.config_path();
    if !config_path.exists() {
        return Err(WgError::NotProvisioned(config_path));
    }
    if let Some(device) = resolve_device(&cfg.interface)? {
        return Ok(StartOutcome::AlreadyRunning { device });
    }
    // `wg-quick` accepte un chemin complet, ce qui permet un `config_dir`
    // en dehors de /etc/wireguard.
    run(WG_QUICK, &["up".as_ref(), config_path.as_os_str()])?;
    let device = resolve_device(&cfg.interface)?.unwrap_or_else(|| cfg.interface.clone());
    Ok(StartOutcome::Started { device })
}

/// Descend l'interface via `wg-quick down`.
///
/// Renvoie [`StopOutcome::AlreadyStopped`] si elle ne tournait pas.
pub fn stop(cfg: &ServerConfig) -> Result<StopOutcome> {
    cfg.validate()?;
    if resolve_device(&cfg.interface)?.is_none() {
        return Ok(StopOutcome::AlreadyStopped);
    }
    // `wg-quick down` attend le nom logique (`wg0`) ou le chemin de conf, pas
    // le périphérique résolu : c'est lui qui relit le fichier `.name`.
    let config_path = cfg.config_path();
    let target = if config_path.exists() {
        config_path.into_os_string()
    } else {
        cfg.interface.clone().into()
    };
    run(WG_QUICK, &["down".as_ref(), target.as_os_str()])?;
    Ok(StopOutcome::Stopped)
}

/// État courant de l'interface, ou `None` si elle n'est pas montée.
pub fn status(cfg: &ServerConfig) -> Result<Option<Status>> {
    let Some(device) = resolve_device(&cfg.interface)? else {
        return Ok(None);
    };
    let details = run(WG, &["show".as_ref(), device.as_ref()])?;
    Ok(Some(Status { device, details }))
}

/// Indique si l'interface est actuellement montée.
pub fn is_running(interface: &str) -> Result<bool> {
    Ok(resolve_device(interface)?.is_some())
}

/// Résout le périphérique réel derrière une interface WireGuard.
///
/// Sous Linux le périphérique porte le nom de l'interface (`wg0`). Sous macOS,
/// `wg-quick` crée un `utunN` et écrit la correspondance dans
/// `/var/run/wireguard/<interface>.name` ; c'est ce nom-là que `wg` comprend.
/// Renvoie `None` si l'interface n'est pas montée.
pub fn resolve_device(interface: &str) -> Result<Option<String>> {
    if wg_show_succeeds(interface)? {
        return Ok(Some(interface.to_string()));
    }
    match device_name_file(Path::new(RUN_DIR), interface)? {
        // Le fichier `.name` survit à un arrêt brutal : on ne le croit que si
        // `wg` reconnaît encore le périphérique qu'il désigne.
        Some(device) if wg_show_succeeds(&device)? => Ok(Some(device)),
        _ => Ok(None),
    }
}

/// Lit `<dir>/<interface>.name`, le fichier de correspondance de `wg-quick`.
///
/// `Ok(None)` signifie « pas de correspondance » ; un refus de droits devient
/// une erreur, sinon un tunnel actif passerait pour arrêté faute de sudo.
fn device_name_file(dir: &Path, interface: &str) -> Result<Option<String>> {
    let path = dir.join(format!("{interface}.name"));
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            return Err(WgError::PermissionDenied(format!("lecture de {}", path.display())))
        }
        Err(e) => return Err(WgError::io(&path, e)),
    };
    let name = raw.trim();
    Ok((!name.is_empty()).then(|| name.to_string()))
}

fn wg_show_succeeds(device: &str) -> Result<bool> {
    let output = Command::new(WG)
        .args(["show", device])
        .output()
        .map_err(|e| binary_error(WG, e))?;
    if output.status.success() {
        return Ok(true);
    }
    // `wg show` a besoin des droits root : sans eux il échoue exactement comme
    // pour une interface absente, ce qui ferait passer un tunnel actif pour
    // arrêté. On distingue les deux plutôt que de mentir.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("Operation not permitted") || stderr.contains("Permission denied") {
        return Err(WgError::PermissionDenied(format!("wg show {device}")));
    }
    Ok(false)
}

fn reuse_existing(config_path: &Path) -> Result<Provisioning> {
    let existing = fs::read_to_string(config_path).map_err(|e| WgError::io(config_path, e))?;
    let private = config::extract_private_key(&existing).ok_or_else(|| {
        WgError::InvalidConfig(format!(
            "{} ne contient pas de PrivateKey",
            config_path.display()
        ))
    })?;
    let keypair = KeyPair::from_private_b64(private)?;
    Ok(Provisioning {
        public_key: keypair.public_b64(),
        config_path: config_path.to_path_buf(),
        created: false,
    })
}

fn ensure_config_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).map_err(|e| WgError::io(dir, e))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| WgError::io(dir, e))
}

/// Écrit un fichier sensible en 0600, en le créant avec les bons droits dès
/// l'ouverture pour ne jamais l'exposer, même brièvement.
fn write_secret(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| WgError::io(path, e))?;
    file.write_all(contents.as_bytes())
        .map_err(|e| WgError::io(path, e))?;
    // Un fichier préexistant conserve ses droits : on les force.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| WgError::io(path, e))
}

fn write_public(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).map_err(|e| WgError::io(path, e))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).map_err(|e| WgError::io(path, e))
}

fn run(bin: &'static str, args: &[&std::ffi::OsStr]) -> Result<String> {
    let output = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| binary_error(bin, e))?;

    if !output.status.success() {
        let rendered = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        return Err(WgError::CommandFailed {
            cmd: format!("{bin} {rendered}"),
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn binary_error(bin: &'static str, err: std::io::Error) -> WgError {
    if err.kind() == ErrorKind::NotFound {
        WgError::MissingBinary(bin)
    } else {
        WgError::io(bin, err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_cfg(name: &str) -> ServerConfig {
        let dir = std::env::temp_dir().join(format!("perses-wg-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        ServerConfig {
            config_dir: dir,
            ..Default::default()
        }
    }

    #[test]
    fn cold_start_writes_key_and_config_with_tight_permissions() {
        let cfg = temp_cfg("provision");
        let out = cold_start(&cfg, false).unwrap();

        assert!(out.created);
        assert_eq!(out.config_path, cfg.config_path());
        for path in [cfg.config_path(), cfg.private_key_path()] {
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{} devrait être en 0600", path.display());
        }
        let written = fs::read_to_string(cfg.config_path()).unwrap();
        assert!(written.contains("[Interface]"));
        assert_eq!(
            fs::read_to_string(cfg.public_key_path()).unwrap().trim(),
            out.public_key
        );

        fs::remove_dir_all(&cfg.config_dir).unwrap();
    }

    #[test]
    fn cold_start_is_idempotent_and_force_rotates_keys() {
        let cfg = temp_cfg("idempotent");
        let first = cold_start(&cfg, false).unwrap();
        let second = cold_start(&cfg, false).unwrap();
        assert!(!second.created);
        assert_eq!(first.public_key, second.public_key);

        let forced = cold_start(&cfg, true).unwrap();
        assert!(forced.created);
        assert_ne!(first.public_key, forced.public_key);

        fs::remove_dir_all(&cfg.config_dir).unwrap();
    }

    #[test]
    fn start_without_provisioning_reports_not_provisioned() {
        let cfg = temp_cfg("unprovisioned");
        match start(&cfg) {
            Err(WgError::NotProvisioned(path)) => assert_eq!(path, cfg.config_path()),
            other => panic!("attendu NotProvisioned, obtenu {other:?}"),
        }
    }

    #[test]
    fn device_name_file_reads_the_wg_quick_mapping() {
        let dir = std::env::temp_dir().join(format!("perses-name-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        assert_eq!(device_name_file(&dir, "wg0").unwrap(), None);

        fs::write(dir.join("wg0.name"), "utun11\n").unwrap();
        assert_eq!(
            device_name_file(&dir, "wg0").unwrap(),
            Some("utun11".to_string())
        );

        // Un fichier vide ne doit pas produire un nom de périphérique vide.
        fs::write(dir.join("wg1.name"), "\n").unwrap();
        assert_eq!(device_name_file(&dir, "wg1").unwrap(), None);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn invalid_interface_name_never_reaches_the_filesystem() {
        let mut cfg = temp_cfg("invalid");
        cfg.interface = "wg0; rm -rf /".to_string();
        assert!(matches!(
            cold_start(&cfg, false),
            Err(WgError::InvalidConfig(_))
        ));
        assert!(!PathBuf::from(&cfg.config_dir).exists());
    }
}
