//! État courant des pairs d'une interface, lu dans `wg show <device> dump`.
//!
//! Le format `dump` est fait pour être lu par un programme : une ligne par
//! pair, des champs séparés par des tabulations, et rien d'autre. C'est ce
//! qui permet de rattacher une adresse vue dans le tunnel à la clé publique
//! du client qui l'utilise.
//!
//! Nécessite les droits root, comme toute lecture d'une interface WireGuard.

use std::net::IpAddr;

use super::error::{Result, WgError};
use super::server;

/// Valeur que `wg` écrit pour un champ vide.
const NONE: &str = "(none)";
/// Valeur que `wg` écrit pour un réglage désactivé.
const OFF: &str = "off";

/// Ce qu'un pair présente à un instant donné.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatus {
    /// Clé publique du client, en base64 — son identité.
    pub public_key: String,
    /// Adresse publique d'où il parle, `None` s'il ne s'est jamais manifesté.
    pub endpoint: Option<String>,
    /// Adresses routées vers lui, en notation CIDR.
    pub allowed_ips: Vec<String>,
    /// Horodatage Unix de la dernière poignée de main, `None` si jamais.
    pub latest_handshake: Option<u64>,
    /// Octets reçus de ce pair depuis le montage de l'interface.
    pub transfer_rx: u64,
    /// Octets qui lui ont été envoyés.
    pub transfer_tx: u64,
    /// Keepalive en secondes, `None` s'il est désactivé.
    pub persistent_keepalive: Option<u16>,
}

/// Instantané d'une interface et de ses pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceStatus {
    /// Périphérique interrogé (`wg0` sous Linux, `utunN` sous macOS).
    pub device: String,
    /// Clé publique du serveur.
    pub public_key: String,
    /// Port UDP d'écoute.
    pub listen_port: u16,
    pub peers: Vec<PeerStatus>,
}

impl DeviceStatus {
    /// Rend le pair à qui appartient une adresse du tunnel.
    ///
    /// Un pair peut annoncer plusieurs préfixes, et plusieurs pairs peuvent
    /// en annoncer d'imbriqués : on retient le plus précis, comme le ferait
    /// une table de routage. Sans cela un pair « passerelle » en `0.0.0.0/0`
    /// s'attribuerait le trafic de tous les autres.
    pub fn peer_for(&self, ip: IpAddr) -> Option<&PeerStatus> {
        self.peers
            .iter()
            .filter_map(|peer| {
                peer.allowed_ips
                    .iter()
                    .filter_map(|cidr| match_len(cidr, ip))
                    .max()
                    .map(|len| (len, peer))
            })
            .max_by_key(|(len, _)| *len)
            .map(|(_, peer)| peer)
    }
}

/// Interroge `wg show <device> dump`.
pub fn dump(device: &str) -> Result<DeviceStatus> {
    let raw = server::run(
        super::server::WG,
        &["show".as_ref(), device.as_ref(), "dump".as_ref()],
    )?;
    parse(device, &raw)
}

/// Découpe la sortie de `wg show … dump`.
///
/// La première ligne décrit l'interface (4 champs), les suivantes les pairs
/// (8 champs). Une ligne au mauvais gabarit est ignorée plutôt que fatale :
/// une version de `wg` qui ajouterait un champ ne doit pas tout arrêter.
fn parse(device: &str, raw: &str) -> Result<DeviceStatus> {
    let mut lines = raw.lines().filter(|line| !line.trim().is_empty());

    let header: Vec<&str> = lines
        .next()
        .ok_or_else(|| WgError::InvalidConfig(format!("wg show {device} dump: sortie vide")))?
        .split('\t')
        .collect();
    if header.len() < 3 {
        return Err(WgError::InvalidConfig(format!(
            "wg show {device} dump: en-tête illisible"
        )));
    }

    Ok(DeviceStatus {
        device: device.to_string(),
        // Le champ 0 est la clé *privée* du serveur : on ne la lit pas.
        public_key: header[1].to_string(),
        listen_port: header[2].parse().unwrap_or_default(),
        peers: lines.filter_map(peer).collect(),
    })
}

fn peer(line: &str) -> Option<PeerStatus> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() < 8 {
        return None;
    }
    Some(PeerStatus {
        public_key: fields[0].to_string(),
        // Le champ 1 est la clé pré-partagée : un secret, qui reste ici.
        endpoint: optional(fields[2]).map(str::to_string),
        allowed_ips: optional(fields[3])
            .map(|ips| ips.split(',').map(|ip| ip.trim().to_string()).collect())
            .unwrap_or_default(),
        // `wg` écrit 0 pour « jamais » : une date nulle serait trompeuse.
        latest_handshake: fields[4].parse().ok().filter(|&t| t > 0),
        transfer_rx: fields[5].parse().unwrap_or_default(),
        transfer_tx: fields[6].parse().unwrap_or_default(),
        persistent_keepalive: optional(fields[7]).and_then(|k| k.parse().ok()),
    })
}

/// Traduit les marqueurs de `wg` en absence de valeur.
fn optional(field: &str) -> Option<&str> {
    let field = field.trim();
    (!field.is_empty() && field != NONE && field != OFF).then_some(field)
}

/// Longueur du préfixe si `ip` tombe dans `cidr`, `None` sinon.
///
/// C'est cette longueur qui départage deux pairs dont les préfixes se
/// recouvrent : le plus long gagne.
fn match_len(cidr: &str, ip: IpAddr) -> Option<u32> {
    let (base, prefix) = match cidr.split_once('/') {
        Some((base, len)) => (
            base.trim().parse::<IpAddr>().ok()?,
            len.trim().parse().ok()?,
        ),
        // Une adresse nue vaut un préfixe complet.
        None => (cidr.trim().parse::<IpAddr>().ok()?, u32::MAX),
    };

    let (base, seen) = match (base, ip) {
        (IpAddr::V4(base), IpAddr::V4(seen)) => (base.octets().to_vec(), seen.octets().to_vec()),
        (IpAddr::V6(base), IpAddr::V6(seen)) => (base.octets().to_vec(), seen.octets().to_vec()),
        // Familles différentes : aucun rapport.
        _ => return None,
    };

    let bits = prefix.min((base.len() * 8) as u32);
    shares_prefix(&base, &seen, bits as usize).then_some(bits)
}

/// Compare les `bits` premiers bits de deux adresses.
fn shares_prefix(a: &[u8], b: &[u8], bits: usize) -> bool {
    let whole = bits / 8;
    if a[..whole] != b[..whole] {
        return false;
    }
    match bits % 8 {
        0 => true,
        rest => {
            // Les bits de poids fort de l'octet suivant, les autres ignorés.
            let mask = 0xFFu8 << (8 - rest);
            a[whole] & mask == b[whole] & mask
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &str = "\
sPriv=\tsPub=\t51820\toff
peerA=\t(none)\t203.0.113.7:51820\t10.8.0.2/32\t1757030390\t1024\t2048\t25
peerB=\tpsk=\t(none)\t10.8.0.3/32,fd00::3/128\t0\t0\t0\toff";

    fn status() -> DeviceStatus {
        parse("wg0", DUMP).unwrap()
    }

    #[test]
    fn reads_the_interface_line_without_the_private_key() {
        let status = status();
        assert_eq!(status.public_key, "sPub=");
        assert_eq!(status.listen_port, 51820);
        assert_eq!(status.peers.len(), 2);
    }

    #[test]
    fn reads_a_peer_that_has_already_spoken() {
        let status = status();
        let peer = &status.peers[0];
        assert_eq!(peer.public_key, "peerA=");
        assert_eq!(peer.endpoint.as_deref(), Some("203.0.113.7:51820"));
        assert_eq!(peer.allowed_ips, ["10.8.0.2/32"]);
        assert_eq!(peer.latest_handshake, Some(1757030390));
        assert_eq!((peer.transfer_rx, peer.transfer_tx), (1024, 2048));
        assert_eq!(peer.persistent_keepalive, Some(25));
    }

    #[test]
    fn a_peer_that_never_connected_has_no_endpoint_and_no_handshake() {
        let status = status();
        let peer = &status.peers[1];
        assert_eq!(peer.endpoint, None);
        assert_eq!(peer.latest_handshake, None);
        assert_eq!(peer.persistent_keepalive, None);
        assert_eq!(peer.allowed_ips, ["10.8.0.3/32", "fd00::3/128"]);
    }

    #[test]
    fn matches_a_tunnel_address_to_its_owner() {
        let status = status();
        let owner = |ip: &str| {
            status
                .peer_for(ip.parse().unwrap())
                .map(|p| p.public_key.as_str())
        };
        assert_eq!(owner("10.8.0.2"), Some("peerA="));
        assert_eq!(owner("10.8.0.3"), Some("peerB="));
        assert_eq!(owner("fd00::3"), Some("peerB="));
        assert_eq!(owner("10.8.0.9"), None);
    }

    #[test]
    fn the_most_specific_peer_wins_over_a_catch_all() {
        let mut status = status();
        status.peers.push(PeerStatus {
            public_key: "gateway=".to_string(),
            endpoint: None,
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            latest_handshake: None,
            transfer_rx: 0,
            transfer_tx: 0,
            persistent_keepalive: None,
        });
        let owner = status.peer_for("10.8.0.2".parse().unwrap()).unwrap();
        assert_eq!(owner.public_key, "peerA=");
        // Hors des /32, il ne reste que la route par défaut.
        let owner = status.peer_for("10.8.0.9".parse().unwrap()).unwrap();
        assert_eq!(owner.public_key, "gateway=");
    }

    #[test]
    fn a_prefix_that_does_not_stop_on_a_byte_boundary_is_honoured() {
        assert_eq!(
            match_len("10.8.0.0/20", "10.8.15.1".parse().unwrap()),
            Some(20)
        );
        assert_eq!(match_len("10.8.0.0/20", "10.8.16.1".parse().unwrap()), None);
    }

    #[test]
    fn an_empty_dump_is_an_error_not_an_empty_device() {
        assert!(parse("wg0", "").is_err());
    }

    #[test]
    fn a_truncated_peer_line_is_skipped_rather_than_fatal() {
        let status = parse("wg0", "sPriv=\tsPub=\t51820\toff\npeerA=\t(none)").unwrap();
        assert!(status.peers.is_empty());
    }
}
