//! Décodage d'une requête DNS (RFC 1035).
//!
//! On ne lit que ce qui nous intéresse : l'identifiant, et le nom de la
//! première question. Le reste du paquet est transmis tel quel à l'amont.
//!
//! Format d'un paquet, en octets :
//!
//! ```text
//! 0      2      4        6      8     10     12
//! | ID   |flags |QDCOUNT|ANCOUNT|NSCOUNT|ARCOUNT|  ← en-tête, 12 octets
//! | QNAME…                     |QTYPE |QCLASS|    ← première question
//! ```
//!
//! Un QNAME est une suite de labels préfixés par leur longueur, terminée par
//! un octet nul : `\x07example\x03com\x00` → `example.com`.

/// Taille de l'en-tête DNS, en octets.
pub const HEADER_LEN: usize = 12;
/// Longueur maximale d'un nom, imposée par la RFC.
const MAX_NAME_LEN: usize = 255;
/// Garde-fou contre les pointeurs de compression qui bouclent.
const MAX_POINTERS: usize = 8;

/// Ce qu'on a réussi à extraire d'une requête.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Identifiant choisi par le client, renvoyé tel quel dans la réponse.
    pub id: u16,
    /// Nom demandé, déjà échappé pour un affichage sûr.
    pub name: String,
    /// Type demandé (1 = A, 28 = AAAA, 65 = HTTPS…).
    pub qtype: u16,
}

/// Les façons dont un paquet peut ne pas être une requête exploitable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("paquet trop court: {0} octets")]
    TooShort(usize),
    #[error("ce paquet est une réponse, pas une requête")]
    NotAQuery,
    #[error("aucune question dans le paquet")]
    NoQuestion,
    #[error("paquet tronqué")]
    UnexpectedEnd,
    #[error("nom trop long (max {MAX_NAME_LEN} octets)")]
    NameTooLong,
    #[error("trop de pointeurs de compression (boucle ?)")]
    TooManyPointers,
    #[error("type de label réservé: {0:#04x}")]
    ReservedLabel(u8),
}

/// Extrait la première question d'un paquet DNS.
///
/// `packet` est le datagramme brut reçu du réseau : on ne lui fait aucune
/// confiance, chaque accès est borné.
pub fn parse_query(packet: &[u8]) -> Result<Query, ParseError> {
    if packet.len() < HEADER_LEN {
        return Err(ParseError::TooShort(packet.len()));
    }
    let id = be_u16(packet, 0);
    let flags = be_u16(packet, 2);
    // Bit de poids fort des flags : 0 = requête, 1 = réponse.
    if flags & 0x8000 != 0 {
        return Err(ParseError::NotAQuery);
    }
    if be_u16(packet, 4) == 0 {
        return Err(ParseError::NoQuestion);
    }

    let (name, after_name) = read_name(packet, HEADER_LEN)?;
    let qtype = packet
        .get(after_name..after_name + 2)
        .ok_or(ParseError::UnexpectedEnd)?;
    Ok(Query {
        id,
        name,
        qtype: u16::from_be_bytes([qtype[0], qtype[1]]),
    })
}

/// Lit un nom à partir de `start`, et renvoie la position juste après lui.
fn read_name(packet: &[u8], start: usize) -> Result<(String, usize), ParseError> {
    let mut name = String::new();
    let mut pos = start;
    let mut bytes = 0usize;
    let mut pointers = 0usize;
    // Après un saut, la lecture continue ailleurs : on mémorise où reprendre.
    let mut resume: Option<usize> = None;

    loop {
        let len = *packet.get(pos).ok_or(ParseError::UnexpectedEnd)? as usize;
        match len & 0xC0 {
            // 00xxxxxx : un label ordinaire de `len` octets.
            0x00 => {
                pos += 1;
                if len == 0 {
                    break;
                }
                bytes += len + 1;
                if bytes > MAX_NAME_LEN {
                    return Err(ParseError::NameTooLong);
                }
                let label = packet.get(pos..pos + len).ok_or(ParseError::UnexpectedEnd)?;
                if !name.is_empty() {
                    name.push('.');
                }
                escape_into(label, &mut name);
                pos += len;
            }
            // 11xxxxxx : pointeur de compression vers un offset du paquet.
            0xC0 => {
                let low = *packet.get(pos + 1).ok_or(ParseError::UnexpectedEnd)? as usize;
                pointers += 1;
                if pointers > MAX_POINTERS {
                    return Err(ParseError::TooManyPointers);
                }
                resume.get_or_insert(pos + 2);
                pos = ((len & 0x3F) << 8) | low;
            }
            _ => return Err(ParseError::ReservedLabel(len as u8)),
        }
    }

    if name.is_empty() {
        name.push('.'); // la racine
    }
    Ok((name, resume.unwrap_or(pos)))
}

/// Recopie un label en échappant tout ce qui n'est pas ASCII imprimable.
///
/// Ces octets viennent du réseau et finissent dans un terminal : sans
/// échappement, un client hostile pourrait y glisser des séquences ANSI.
fn escape_into(label: &[u8], out: &mut String) {
    use std::fmt::Write as _;
    for &b in label {
        match b {
            b'.' | b'\\' => {
                out.push('\\');
                out.push(b as char);
            }
            0x21..=0x7E => out.push(b as char),
            _ => {
                let _ = write!(out, "\\{b:03}");
            }
        }
    }
}

fn be_u16(packet: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([packet[at], packet[at + 1]])
}

/// Fabrication de paquets pour les tests du module et ceux du relais.
#[cfg(test)]
pub(crate) mod testing {
    use super::HEADER_LEN;

    /// Construit une requête A minimale pour `name`.
    pub fn query(id: u16, name: &str) -> Vec<u8> {
        let mut packet = Vec::with_capacity(HEADER_LEN + name.len() + 6);
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&[0x01, 0x00]); // flags: requête récursive
        packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        packet.extend_from_slice(&[0x00; 6]); // AN/NS/AR = 0
        for label in name.split('.').filter(|l| !l.is_empty()) {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00); // fin du nom
        packet.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::testing::query;
    use super::*;

    #[test]
    fn reads_the_question_of_a_well_formed_query() {
        let parsed = parse_query(&query(0x1234, "example.com")).unwrap();
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.name, "example.com");
        assert_eq!(parsed.qtype, 1);
    }

    #[test]
    fn reads_a_deep_subdomain() {
        let parsed = parse_query(&query(1, "a.b.c.example.co.uk")).unwrap();
        assert_eq!(parsed.name, "a.b.c.example.co.uk");
    }

    #[test]
    fn rejects_responses_and_stunted_packets() {
        let mut response = query(1, "example.com");
        response[2] |= 0x80; // QR = 1
        assert_eq!(parse_query(&response), Err(ParseError::NotAQuery));

        assert_eq!(parse_query(&[]), Err(ParseError::TooShort(0)));

        let packet = query(1, "example.com");
        assert_eq!(
            parse_query(&packet[..packet.len() - 6]),
            Err(ParseError::UnexpectedEnd)
        );

        let mut no_question = query(1, "example.com");
        no_question[4] = 0;
        no_question[5] = 0;
        assert_eq!(parse_query(&no_question), Err(ParseError::NoQuestion));
    }

    #[test]
    fn a_label_length_past_the_end_does_not_panic() {
        let mut packet = query(1, "example.com");
        packet[HEADER_LEN] = 0xFF; // label de 255 octets dans un paquet plus court
        assert_eq!(parse_query(&packet), Err(ParseError::UnexpectedEnd));
    }

    #[test]
    fn a_pointer_loop_is_stopped() {
        let mut packet = query(1, "example.com");
        packet[HEADER_LEN] = 0xC0; // pointeur…
        packet[HEADER_LEN + 1] = HEADER_LEN as u8; // …vers lui-même
        assert_eq!(parse_query(&packet), Err(ParseError::TooManyPointers));
    }

    #[test]
    fn control_bytes_in_a_label_are_escaped() {
        let mut packet = query(1, "x");
        packet[HEADER_LEN + 1] = 0x1B; // ESC, début d'une séquence ANSI
        let parsed = parse_query(&packet).unwrap();
        assert_eq!(parsed.name, "\\027");
        assert!(!parsed.name.contains('\u{1b}'));
    }
}
