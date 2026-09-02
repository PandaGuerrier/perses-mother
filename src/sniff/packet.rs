//! Épluchage des couches réseau : liaison → IP → UDP.
//!
//! Chaque fonction reçoit une tranche d'octets bruts venue du réseau et rend
//! une sous-tranche, sans jamais recopier : `&'a [u8]` en entrée, `&'a [u8]`
//! en sortie. Le compilateur garantit que ces vues ne survivent pas au tampon
//! de capture qu'elles décrivent.

/// Numéro de protocole de UDP dans un en-tête IP.
const PROTO_UDP: u8 = 17;

/// En-tête de couche liaison présenté par l'interface capturée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// `DLT_NULL` / `DLT_LOOP` : 4 octets de famille d'adresses.
    /// C'est ce que présente un `utunN` sous macOS.
    Null,
    /// `DLT_RAW` : le paquet IP commence directement.
    /// C'est ce que présente un `wg0` sous Linux.
    Raw,
    /// `DLT_EN10MB` : en-tête Ethernet de 14 octets.
    Ethernet,
}

impl LinkType {
    /// Traduit une valeur `DLT_*` de libpcap.
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 | 108 => Some(Self::Null),  // DLT_NULL, DLT_LOOP
            1 => Some(Self::Ethernet),    // DLT_EN10MB
            12 | 14 | 101 => Some(Self::Raw), // DLT_RAW selon les plateformes
            _ => None,
        }
    }

    /// Retire l'en-tête de liaison et rend le paquet IP.
    pub fn strip(self, frame: &[u8]) -> Option<&[u8]> {
        match self {
            Self::Null => frame.get(4..),
            Self::Raw => Some(frame),
            Self::Ethernet => {
                // Les deux octets d'EtherType précèdent la charge utile.
                let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
                match ethertype {
                    0x0800 | 0x86DD => frame.get(14..),
                    _ => None,
                }
            }
        }
    }
}

/// Un datagramme UDP extrait d'une trame.
#[derive(Debug, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Extrait le datagramme UDP d'une trame capturée, s'il y en a un.
///
/// Rend `None` — sans bruit — pour tout ce qui n'est pas de l'UDP sur IP :
/// c'est la majorité du trafic, pas une anomalie.
pub fn udp_datagram(link: LinkType, frame: &[u8]) -> Option<Datagram<'_>> {
    let ip = link.strip(frame)?;
    let (proto, payload) = ip_payload(ip)?;
    if proto != PROTO_UDP {
        return None;
    }
    parse_udp(payload)
}

/// Rend le protocole transporté et la charge utile d'un paquet IPv4 ou IPv6.
fn ip_payload(packet: &[u8]) -> Option<(u8, &[u8])> {
    // Le demi-octet de poids fort donne la version : 4 ou 6.
    match packet.first()? >> 4 {
        4 => ipv4_payload(packet),
        6 => ipv6_payload(packet),
        _ => None,
    }
}

fn ipv4_payload(packet: &[u8]) -> Option<(u8, &[u8])> {
    // IHL : longueur de l'en-tête en mots de 32 bits, minimum 5.
    let header_len = (packet.first()? & 0x0F) as usize * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }
    // Un fragment non initial n'a pas d'en-tête UDP : on ne réassemble pas.
    let fragment_offset = u16::from_be_bytes([packet[6], packet[7]]) & 0x1FFF;
    if fragment_offset != 0 {
        return None;
    }
    // La trame peut être complétée par du bourrage : on se fie au champ de
    // longueur, borné par ce qu'on a réellement capturé.
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let end = total_len.clamp(header_len, packet.len());
    Some((packet[9], packet.get(header_len..end)?))
}

fn ipv6_payload(packet: &[u8]) -> Option<(u8, &[u8])> {
    if packet.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let end = (40 + payload_len).min(packet.len());
    let mut next_header = packet[6];
    let mut rest = packet.get(40..end)?;

    // Les en-têtes d'extension partagent tous la forme (suivant, longueur).
    for _ in 0..4 {
        match next_header {
            0 | 43 | 60 => {
                let len = (*rest.get(1)? as usize + 1) * 8;
                next_header = *rest.first()?;
                rest = rest.get(len..)?;
            }
            _ => return Some((next_header, rest)),
        }
    }
    None
}

fn parse_udp(datagram: &[u8]) -> Option<Datagram<'_>> {
    if datagram.len() < 8 {
        return None;
    }
    // Le champ longueur inclut les 8 octets d'en-tête.
    let len = u16::from_be_bytes([datagram[4], datagram[5]]) as usize;
    let end = len.clamp(8, datagram.len());
    Some(Datagram {
        src_port: u16::from_be_bytes([datagram[0], datagram[1]]),
        dst_port: u16::from_be_bytes([datagram[2], datagram[3]]),
        payload: datagram.get(8..end)?,
    })
}

/// Fabrication de trames pour les tests.
#[cfg(test)]
pub(crate) mod testing {
    /// Encapsule `payload` dans UDP/IPv4/DLT_NULL, comme un `utunN` le rendrait.
    pub fn null_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;

        let mut frame = vec![0x02, 0x00, 0x00, 0x00]; // AF_INET
        frame.extend_from_slice(&[0x45, 0x00]); // version 4, IHL 5
        frame.extend_from_slice(&(total_len as u16).to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // id, pas de fragment
        frame.extend_from_slice(&[64, 17]); // TTL, protocole UDP
        frame.extend_from_slice(&[0x00, 0x00]); // somme de contrôle ignorée
        frame.extend_from_slice(&[10, 8, 0, 2]); // source
        frame.extend_from_slice(&[10, 8, 0, 1]); // destination

        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]); // somme de contrôle ignorée
        frame.extend_from_slice(payload);
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::testing::null_ipv4_udp;
    use super::*;

    #[test]
    fn link_types_map_to_the_right_header_length() {
        assert_eq!(LinkType::from_raw(0), Some(LinkType::Null));
        assert_eq!(LinkType::from_raw(12), Some(LinkType::Raw));
        assert_eq!(LinkType::from_raw(1), Some(LinkType::Ethernet));
        assert_eq!(LinkType::from_raw(999), None);

        assert_eq!(LinkType::Raw.strip(&[0x45, 0x00]), Some(&[0x45, 0x00][..]));
        assert_eq!(LinkType::Null.strip(&[2, 0, 0, 0, 0x45]), Some(&[0x45][..]));
        assert_eq!(LinkType::Null.strip(&[2, 0]), None, "trame trop courte");
    }

    #[test]
    fn extracts_udp_from_a_utun_frame() {
        let frame = null_ipv4_udp(53000, 53, b"charge utile");
        let datagram = udp_datagram(LinkType::Null, &frame).unwrap();
        assert_eq!(datagram.src_port, 53000);
        assert_eq!(datagram.dst_port, 53);
        assert_eq!(datagram.payload, b"charge utile");
    }

    #[test]
    fn ignores_tcp_and_non_ip_traffic() {
        let mut frame = null_ipv4_udp(1, 2, b"x");
        frame[13] = 6; // protocole TCP
        assert_eq!(udp_datagram(LinkType::Null, &frame), None);

        let mut frame = null_ipv4_udp(1, 2, b"x");
        frame[4] = 0x75; // version IP 7 : inconnue
        assert_eq!(udp_datagram(LinkType::Null, &frame), None);
    }

    #[test]
    fn ignores_non_initial_fragments() {
        let mut frame = null_ipv4_udp(1, 53, b"x");
        frame[10] = 0x00;
        frame[11] = 0x02; // décalage de fragment non nul
        assert_eq!(udp_datagram(LinkType::Null, &frame), None);
    }

    #[test]
    fn trailing_padding_is_not_mistaken_for_payload() {
        let mut frame = null_ipv4_udp(1, 53, b"utile");
        frame.extend_from_slice(&[0xFF; 16]); // bourrage ajouté par la couche liaison
        let datagram = udp_datagram(LinkType::Null, &frame).unwrap();
        assert_eq!(datagram.payload, b"utile");
    }

    #[test]
    fn truncated_frames_never_panic() {
        let frame = null_ipv4_udp(1, 53, b"charge");
        // Toute troncature possible doit rendre None, jamais paniquer.
        for len in 0..frame.len() {
            let _ = udp_datagram(LinkType::Null, &frame[..len]);
        }
    }

    #[test]
    fn reads_udp_over_ipv6() {
        let mut frame = vec![0x02, 0x00, 0x00, 0x00];
        frame.push(0x60); // version 6
        frame.extend_from_slice(&[0x00; 3]);
        frame.extend_from_slice(&[0x00, 0x0D]); // longueur de charge utile
        frame.push(17); // en-tête suivant : UDP
        frame.push(64); // limite de saut
        frame.extend_from_slice(&[0x00; 32]); // adresses source et destination
        frame.extend_from_slice(&[0x00, 0x35, 0x00, 0x35, 0x00, 0x0D, 0x00, 0x00]);
        frame.extend_from_slice(b"abcde");

        let datagram = udp_datagram(LinkType::Null, &frame).unwrap();
        assert_eq!(datagram.dst_port, 53);
        assert_eq!(datagram.payload, b"abcde");
    }
}
