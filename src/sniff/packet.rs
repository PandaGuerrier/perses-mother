//! Épluchage des couches réseau : liaison → IP → UDP.
//!
//! Chaque fonction reçoit une tranche d'octets bruts venue du réseau et rend
//! une sous-tranche, sans jamais recopier : `&'a [u8]` en entrée, `&'a [u8]`
//! en sortie. Le compilateur garantit que ces vues ne survivent pas au tampon
//! de capture qu'elles décrivent.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Numéros de protocole dans un en-tête IP.
const PROTO_TCP: u8 = 6;
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
    /// `DLT_LINUX_SLL` : en-tête « cooked » de 16 octets.
    LinuxCooked,
    /// `DLT_LINUX_SLL2` : sa version 2, de 20 octets.
    LinuxCooked2,
}

impl LinkType {
    /// Traduit une valeur `DLT_*` de libpcap.
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 | 108 => Some(Self::Null),  // DLT_NULL, DLT_LOOP
            1 => Some(Self::Ethernet),    // DLT_EN10MB
            12 | 14 | 101 => Some(Self::Raw), // DLT_RAW selon les plateformes
            113 => Some(Self::LinuxCooked),   // DLT_LINUX_SLL
            276 => Some(Self::LinuxCooked2),  // DLT_LINUX_SLL2
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
            Self::LinuxCooked => frame.get(16..),
            Self::LinuxCooked2 => frame.get(20..),
        }
    }
}

/// Protocole de transport porté par un paquet IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

/// Un segment de transport extrait d'une trame, avec ses extrémités.
#[derive(Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    pub protocol: Transport,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Extrait le segment TCP ou UDP d'une trame capturée, s'il y en a un.
///
/// Rend `None` — sans bruit — pour tout le reste : trafic non-IP, autres
/// protocoles, fragments. C'est le cas courant, pas une anomalie.
pub fn segment(link: LinkType, frame: &[u8]) -> Option<Segment<'_>> {
    let ip = link.strip(frame)?;
    let packet = ip_payload(ip)?;
    let (protocol, ports_and_payload) = match packet.protocol {
        PROTO_TCP => (Transport::Tcp, parse_tcp(packet.payload)?),
        PROTO_UDP => (Transport::Udp, parse_udp(packet.payload)?),
        _ => return None,
    };
    let (src_port, dst_port, payload) = ports_and_payload;
    Some(Segment {
        protocol,
        src: packet.src,
        dst: packet.dst,
        src_port,
        dst_port,
        payload,
    })
}

/// Ce qu'on retient d'un en-tête IP.
struct IpPacket<'a> {
    protocol: u8,
    src: IpAddr,
    dst: IpAddr,
    payload: &'a [u8],
}

/// Rend le protocole transporté et la charge utile d'un paquet IPv4 ou IPv6.
fn ip_payload(packet: &[u8]) -> Option<IpPacket<'_>> {
    // Le demi-octet de poids fort donne la version : 4 ou 6.
    match packet.first()? >> 4 {
        4 => ipv4_payload(packet),
        6 => ipv6_payload(packet),
        _ => None,
    }
}

fn ipv4_payload(packet: &[u8]) -> Option<IpPacket<'_>> {
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
    Some(IpPacket {
        protocol: packet[9],
        src: IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])),
        dst: IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])),
        payload: packet.get(header_len..end)?,
    })
}

fn ipv6_payload(packet: &[u8]) -> Option<IpPacket<'_>> {
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
            _ => {
                let addr = |at: usize| -> IpAddr {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&packet[at..at + 16]);
                    IpAddr::V6(Ipv6Addr::from(octets))
                };
                return Some(IpPacket {
                    protocol: next_header,
                    src: addr(8),
                    dst: addr(24),
                    payload: rest,
                });
            }
        }
    }
    None
}

type Ports<'a> = (u16, u16, &'a [u8]);

fn parse_udp(datagram: &[u8]) -> Option<Ports<'_>> {
    if datagram.len() < 8 {
        return None;
    }
    // Le champ longueur inclut les 8 octets d'en-tête.
    let len = u16::from_be_bytes([datagram[4], datagram[5]]) as usize;
    let end = len.clamp(8, datagram.len());
    Some((
        u16::from_be_bytes([datagram[0], datagram[1]]),
        u16::from_be_bytes([datagram[2], datagram[3]]),
        datagram.get(8..end)?,
    ))
}

fn parse_tcp(segment: &[u8]) -> Option<Ports<'_>> {
    if segment.len() < 20 {
        return None;
    }
    // Les 4 bits de poids fort de l'octet 12 donnent la taille de l'en-tête,
    // en mots de 32 bits : les options TCP la font varier.
    let header_len = (segment[12] >> 4) as usize * 4;
    if header_len < 20 {
        return None;
    }
    Some((
        u16::from_be_bytes([segment[0], segment[1]]),
        u16::from_be_bytes([segment[2], segment[3]]),
        segment.get(header_len..)?,
    ))
}

/// Fabrication de trames pour les tests.
#[cfg(test)]
pub(crate) mod testing {
    /// Encapsule `payload` dans UDP/IPv4/DLT_NULL, comme un `utunN` le rendrait.
    pub fn null_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut transport = src_port.to_be_bytes().to_vec();
        transport.extend_from_slice(&dst_port.to_be_bytes());
        transport.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        transport.extend_from_slice(&[0x00, 0x00]); // somme de contrôle ignorée
        transport.extend_from_slice(payload);
        null_ipv4(super::PROTO_UDP, &transport)
    }

    /// Encapsule `payload` dans TCP/IPv4/DLT_NULL.
    pub fn null_ipv4_tcp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut transport = src_port.to_be_bytes().to_vec();
        transport.extend_from_slice(&dst_port.to_be_bytes());
        transport.extend_from_slice(&[0x00; 8]); // numéros de séquence
        transport.extend_from_slice(&[0x50, 0x18]); // en-tête de 20 octets, ACK+PSH
        transport.extend_from_slice(&[0xFF, 0xFF]); // fenêtre
        transport.extend_from_slice(&[0x00; 4]); // somme de contrôle, urgent
        transport.extend_from_slice(payload);
        null_ipv4(super::PROTO_TCP, &transport)
    }

    fn null_ipv4(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let total_len = 20 + transport.len();

        let mut frame = vec![0x02, 0x00, 0x00, 0x00]; // AF_INET
        frame.extend_from_slice(&[0x45, 0x00]); // version 4, IHL 5
        frame.extend_from_slice(&(total_len as u16).to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // id, pas de fragment
        frame.extend_from_slice(&[64, protocol]); // TTL, protocole
        frame.extend_from_slice(&[0x00, 0x00]); // somme de contrôle ignorée
        frame.extend_from_slice(&[10, 8, 0, 2]); // source
        frame.extend_from_slice(&[10, 8, 0, 1]); // destination
        frame.extend_from_slice(transport);
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{null_ipv4_tcp, null_ipv4_udp};
    use super::*;

    #[test]
    fn link_types_map_to_the_right_header_length() {
        assert_eq!(LinkType::from_raw(0), Some(LinkType::Null));
        assert_eq!(LinkType::from_raw(12), Some(LinkType::Raw));
        assert_eq!(LinkType::from_raw(1), Some(LinkType::Ethernet));
        assert_eq!(LinkType::from_raw(113), Some(LinkType::LinuxCooked));
        assert_eq!(LinkType::from_raw(999), None);

        assert_eq!(LinkType::Raw.strip(&[0x45, 0x00]), Some(&[0x45, 0x00][..]));
        assert_eq!(LinkType::Null.strip(&[2, 0, 0, 0, 0x45]), Some(&[0x45][..]));
        assert_eq!(LinkType::Null.strip(&[2, 0]), None, "trame trop courte");
    }

    #[test]
    fn extracts_udp_from_a_utun_frame() {
        let frame = null_ipv4_udp(53000, 53, b"charge utile");
        let segment = segment(LinkType::Null, &frame).unwrap();
        assert_eq!(segment.protocol, Transport::Udp);
        assert_eq!(segment.src.to_string(), "10.8.0.2");
        assert_eq!(segment.src_port, 53000);
        assert_eq!(segment.dst_port, 53);
        assert_eq!(segment.payload, b"charge utile");
    }

    #[test]
    fn extracts_tcp_and_skips_its_options() {
        let frame = null_ipv4_tcp(51000, 443, b"salut");
        let parsed = segment(LinkType::Null, &frame).unwrap();
        assert_eq!(parsed.protocol, Transport::Tcp);
        assert_eq!(parsed.dst_port, 443);
        assert_eq!(parsed.payload, b"salut");

        // En-tête de 24 octets : 4 octets d'options avant la charge utile.
        let mut with_options = null_ipv4_tcp(51000, 443, &[0xAA; 4]);
        let tcp_at = 4 + 20;
        with_options[tcp_at + 12] = 0x60;
        let parsed = segment(LinkType::Null, &with_options).unwrap();
        assert!(parsed.payload.is_empty(), "les options ne sont pas des données");
    }

    #[test]
    fn ignores_traffic_that_is_neither_tcp_nor_udp() {
        let mut frame = null_ipv4_udp(1, 2, b"x");
        frame[13] = 1; // ICMP : ni TCP ni UDP
        assert!(segment(LinkType::Null, &frame).is_none());

        let mut frame = null_ipv4_udp(1, 2, b"x");
        frame[4] = 0x75; // version IP 7 : inconnue
        assert!(segment(LinkType::Null, &frame).is_none());
    }

    #[test]
    fn ignores_non_initial_fragments() {
        let mut frame = null_ipv4_udp(1, 53, b"x");
        frame[10] = 0x00;
        frame[11] = 0x02; // décalage de fragment non nul
        assert!(segment(LinkType::Null, &frame).is_none());
    }

    #[test]
    fn trailing_padding_is_not_mistaken_for_payload() {
        let mut frame = null_ipv4_udp(1, 53, b"utile");
        frame.extend_from_slice(&[0xFF; 16]); // bourrage ajouté par la couche liaison
        let datagram = segment(LinkType::Null, &frame).unwrap();
        assert_eq!(datagram.payload, b"utile");
    }

    #[test]
    fn truncated_frames_never_panic() {
        let frame = null_ipv4_udp(1, 53, b"charge");
        // Toute troncature possible doit rendre None, jamais paniquer.
        for len in 0..frame.len() {
            let _ = segment(LinkType::Null, &frame[..len]);
        }
        let tcp = null_ipv4_tcp(1, 443, b"charge");
        for len in 0..tcp.len() {
            let _ = segment(LinkType::Null, &tcp[..len]);
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

        let datagram = segment(LinkType::Null, &frame).unwrap();
        assert_eq!(datagram.dst_port, 53);
        assert_eq!(datagram.payload, b"abcde");
        assert!(datagram.src.is_ipv6());
    }
}
