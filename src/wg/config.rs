//! Description et rendu de la configuration d'un serveur WireGuard.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use super::error::{Result, WgError};
use super::keys;

/// Répertoire standard lu par `wg-quick`.
pub const DEFAULT_CONFIG_DIR: &str = "/etc/wireguard";
/// Nom d'interface par défaut.
pub const DEFAULT_INTERFACE: &str = "wg0";
/// Port UDP d'écoute par défaut.
pub const DEFAULT_LISTEN_PORT: u16 = 51820;
/// Sous-réseau du serveur par défaut.
pub const DEFAULT_ADDRESS: &str = "10.8.0.1/24";

/// Un pair autorisé à se connecter au serveur.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Clé publique du client, en base64.
    pub public_key: String,
    /// Adresses routées vers ce pair, ex. `["10.8.0.2/32"]`.
    pub allowed_ips: Vec<String>,
    /// Clé pré-partagée optionnelle (défense supplémentaire post-quantique).
    pub preshared_key: Option<String>,
    /// Keepalive en secondes, utile derrière un NAT.
    pub persistent_keepalive: Option<u16>,
    /// Commentaire libre écrit au-dessus de la section.
    pub name: Option<String>,
}

impl Peer {
    /// Pair minimal : une clé publique et une IP dans le tunnel.
    pub fn new(public_key: impl Into<String>, allowed_ips: impl Into<String>) -> Self {
        Self {
            public_key: public_key.into(),
            allowed_ips: vec![allowed_ips.into()],
            preshared_key: None,
            persistent_keepalive: None,
            name: None,
        }
    }

    fn validate(&self) -> Result<()> {
        keys::validate_key_b64(&self.public_key)?;
        if let Some(psk) = &self.preshared_key {
            keys::validate_key_b64(psk)?;
        }
        if self.allowed_ips.is_empty() {
            return Err(WgError::InvalidConfig(format!(
                "le pair {} n'a aucun AllowedIPs",
                self.public_key
            )));
        }
        Ok(())
    }
}

/// Paramètres du serveur, indépendants des clés.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Nom de l'interface (`wg0`), qui donne aussi son nom au fichier de conf.
    pub interface: String,
    /// Répertoire des fichiers de configuration.
    pub config_dir: PathBuf,
    /// Adresse du serveur dans le tunnel, en notation CIDR.
    pub address: String,
    /// Port UDP d'écoute.
    pub listen_port: u16,
    /// Interface de sortie ; si renseignée, des règles de NAT sont ajoutées.
    pub wan_interface: Option<String>,
    /// Serveurs DNS poussés aux clients.
    pub dns: Vec<String>,
    /// MTU forcée, si l'auto-détection de `wg-quick` ne convient pas.
    pub mtu: Option<u32>,
    /// Pairs déclarés dans le fichier de configuration.
    pub peers: Vec<Peer>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            interface: DEFAULT_INTERFACE.to_string(),
            config_dir: PathBuf::from(DEFAULT_CONFIG_DIR),
            address: DEFAULT_ADDRESS.to_string(),
            listen_port: DEFAULT_LISTEN_PORT,
            wan_interface: None,
            dns: Vec::new(),
            mtu: None,
            peers: Vec::new(),
        }
    }
}

impl ServerConfig {
    /// Chemin du fichier `wg-quick`, ex. `/etc/wireguard/wg0.conf`.
    pub fn config_path(&self) -> PathBuf {
        self.config_dir.join(format!("{}.conf", self.interface))
    }

    /// Chemin de la clé privée du serveur, ex. `/etc/wireguard/wg0.key`.
    pub fn private_key_path(&self) -> PathBuf {
        self.config_dir.join(format!("{}.key", self.interface))
    }

    /// Chemin de la clé publique du serveur, ex. `/etc/wireguard/wg0.pub`.
    pub fn public_key_path(&self) -> PathBuf {
        self.config_dir.join(format!("{}.pub", self.interface))
    }

    /// Vérifie la cohérence avant toute écriture sur disque.
    pub fn validate(&self) -> Result<()> {
        if self.interface.is_empty()
            || !self
                .interface
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(WgError::InvalidConfig(format!(
                "nom d'interface invalide: {:?}",
                self.interface
            )));
        }
        if !self.address.contains('/') {
            return Err(WgError::InvalidConfig(format!(
                "l'adresse {:?} doit être en notation CIDR (ex. 10.8.0.1/24)",
                self.address
            )));
        }
        if self.listen_port == 0 {
            return Err(WgError::InvalidConfig(
                "le port d'écoute ne peut pas être 0".to_string(),
            ));
        }
        for peer in &self.peers {
            peer.validate()?;
        }
        Ok(())
    }

    /// Rend le fichier `wg0.conf` à partir de la clé privée du serveur.
    pub fn render(&self, private_key_b64: &str) -> Result<String> {
        self.validate()?;
        keys::validate_key_b64(private_key_b64)?;

        let mut out = String::new();
        let _ = writeln!(
            out,
            "# Généré par perses-mother — ne pas éditer à la main.\n[Interface]"
        );
        let _ = writeln!(out, "Address = {}", self.address);
        let _ = writeln!(out, "ListenPort = {}", self.listen_port);
        let _ = writeln!(out, "PrivateKey = {private_key_b64}");
        if !self.dns.is_empty() {
            let _ = writeln!(out, "DNS = {}", self.dns.join(", "));
        }
        if let Some(mtu) = self.mtu {
            let _ = writeln!(out, "MTU = {mtu}");
        }
        if let Some(wan) = &self.wan_interface {
            let _ = writeln!(out, "PostUp = {}", nat_up(&self.interface, wan));
            let _ = writeln!(out, "PostDown = {}", nat_down(&self.interface, wan));
        }

        for peer in &self.peers {
            out.push('\n');
            if let Some(name) = &peer.name {
                let _ = writeln!(out, "# {name}");
            }
            let _ = writeln!(out, "[Peer]");
            let _ = writeln!(out, "PublicKey = {}", peer.public_key);
            if let Some(psk) = &peer.preshared_key {
                let _ = writeln!(out, "PresharedKey = {psk}");
            }
            let _ = writeln!(out, "AllowedIPs = {}", peer.allowed_ips.join(", "));
            if let Some(keepalive) = peer.persistent_keepalive {
                let _ = writeln!(out, "PersistentKeepalive = {keepalive}");
            }
        }
        Ok(out)
    }
}

/// Extrait la valeur `PrivateKey` d'un fichier de configuration existant.
pub fn extract_private_key(config: &str) -> Option<&str> {
    config.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim().eq_ignore_ascii_case("PrivateKey")).then(|| value.trim())
    })
}

/// Nom d'interface déduit d'un chemin de configuration.
pub fn interface_from_path(path: &Path) -> Option<&str> {
    path.file_stem()?.to_str()
}

fn nat_up(interface: &str, wan: &str) -> String {
    format!(
        "iptables -A FORWARD -i {interface} -j ACCEPT; \
         iptables -A FORWARD -o {interface} -j ACCEPT; \
         iptables -t nat -A POSTROUTING -o {wan} -j MASQUERADE"
    )
}

fn nat_down(interface: &str, wan: &str) -> String {
    format!(
        "iptables -D FORWARD -i {interface} -j ACCEPT; \
         iptables -D FORWARD -o {interface} -j ACCEPT; \
         iptables -t nat -D POSTROUTING -o {wan} -j MASQUERADE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::keys::KeyPair;

    fn cfg() -> ServerConfig {
        ServerConfig {
            config_dir: PathBuf::from("/tmp/wg-test"),
            ..Default::default()
        }
    }

    #[test]
    fn paths_are_derived_from_interface() {
        let c = cfg();
        assert_eq!(c.config_path(), PathBuf::from("/tmp/wg-test/wg0.conf"));
        assert_eq!(c.private_key_path(), PathBuf::from("/tmp/wg-test/wg0.key"));
    }

    #[test]
    fn render_contains_interface_section() {
        let kp = KeyPair::generate();
        let rendered = cfg().render(&kp.private_b64()).unwrap();
        assert!(rendered.contains("[Interface]"));
        assert!(rendered.contains("ListenPort = 51820"));
        assert!(rendered.contains(&format!("PrivateKey = {}", kp.private_b64())));
        assert!(!rendered.contains("[Peer]"));
    }

    #[test]
    fn render_emits_nat_rules_only_with_wan_interface() {
        let kp = KeyPair::generate();
        assert!(!cfg().render(&kp.private_b64()).unwrap().contains("PostUp"));

        let mut c = cfg();
        c.wan_interface = Some("eth0".to_string());
        let rendered = c.render(&kp.private_b64()).unwrap();
        assert!(rendered.contains("POSTROUTING -o eth0 -j MASQUERADE"));
        assert!(rendered.contains("PostDown"));
    }

    #[test]
    fn render_emits_one_section_per_peer() {
        let server = KeyPair::generate();
        let client = KeyPair::generate();
        let mut c = cfg();
        let mut peer = Peer::new(client.public_b64(), "10.8.0.2/32");
        peer.name = Some("laptop".to_string());
        peer.persistent_keepalive = Some(25);
        c.peers.push(peer);

        let rendered = c.render(&server.private_b64()).unwrap();
        assert!(rendered.contains("# laptop"));
        assert!(rendered.contains(&format!("PublicKey = {}", client.public_b64())));
        assert!(rendered.contains("AllowedIPs = 10.8.0.2/32"));
        assert!(rendered.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn render_rejects_invalid_input() {
        let kp = KeyPair::generate();
        let mut c = cfg();
        c.address = "10.8.0.1".to_string();
        assert!(c.render(&kp.private_b64()).is_err());

        let mut c = cfg();
        c.peers.push(Peer::new("pas-une-cle", "10.8.0.2/32"));
        assert!(c.render(&kp.private_b64()).is_err());

        assert!(cfg().render("pas-une-cle").is_err());
    }

    #[test]
    fn extract_private_key_reads_back_rendered_config() {
        let kp = KeyPair::generate();
        let rendered = cfg().render(&kp.private_b64()).unwrap();
        assert_eq!(extract_private_key(&rendered), Some(kp.private_b64().as_str()));
        assert_eq!(extract_private_key("[Interface]\n"), None);
    }
}
