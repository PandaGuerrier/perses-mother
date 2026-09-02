//! Extraction du SNI d'un ClientHello TLS.
//!
//! Le SNI (*Server Name Indication*) est le nom d'hôte que le client annonce
//! en clair au tout début de la poignée de main, avant tout chiffrement — il
//! reste lisible même quand le DNS du client, lui, est chiffré.
//!
//! Emboîtement des couches, chacune préfixée par sa longueur :
//!
//! ```text
//! record TLS      : 0x16 | version(2) | longueur(2) | …
//!  handshake      : 0x01 | longueur(3) | …
//!   ClientHello   : version(2) | aléa(32) | session | ciphers | compression
//!    extensions   : longueur(2) | [ type(2) | longueur(2) | données ]…
//!     server_name : longueur(2) | 0x00 | longueur(2) | « github.com »
//! ```

use crate::name;

/// Type d'enregistrement TLS « handshake ».
const RECORD_HANDSHAKE: u8 = 0x16;
/// Type de message de poignée de main « ClientHello ».
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
/// Numéro de l'extension `server_name`.
const EXT_SERVER_NAME: u16 = 0x0000;
/// Type d'entrée `host_name` dans cette extension.
const NAME_TYPE_HOST: u8 = 0x00;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TlsError {
    #[error("ce n'est pas un ClientHello")]
    NotAClientHello,
    /// Le message est valide mais tronqué : il continue dans le segment suivant.
    #[error("message incomplet")]
    Incomplete,
    #[error("message mal formé")]
    Malformed,
    #[error("aucune extension server_name")]
    NoServerName,
}

/// Rend le nom d'hôte annoncé par un ClientHello.
///
/// `stream` est le début des données TCP du client. L'erreur
/// [`TlsError::Incomplete`] signale qu'il faut attendre le segment suivant :
/// avec les échanges de clés post-quantiques, un ClientHello dépasse souvent
/// la MTU et arrive en deux morceaux.
pub fn server_name(stream: &[u8]) -> Result<String, TlsError> {
    let mut reader = Reader::new(stream);

    if reader.u8()? != RECORD_HANDSHAKE {
        return Err(TlsError::NotAClientHello);
    }
    reader.skip(2)?; // version du record, non significative ici
    let record_len = reader.u16()? as usize;
    let mut record = Reader::new(reader.take(record_len)?);

    if record.u8()? != HANDSHAKE_CLIENT_HELLO {
        return Err(TlsError::NotAClientHello);
    }
    let handshake_len = record.u24()?;
    let mut hello = Reader::new(record.take(handshake_len)?);

    hello.skip(2 + 32)?; // version annoncée, puis aléa client
    let session_id = hello.u8()? as usize;
    hello.skip(session_id)?;
    let cipher_suites = hello.u16()? as usize;
    hello.skip(cipher_suites)?;
    let compression = hello.u8()? as usize;
    hello.skip(compression)?;

    // Un ClientHello sans bloc d'extensions est valide (TLS 1.0) : pas de SNI.
    if hello.is_empty() {
        return Err(TlsError::NoServerName);
    }
    let extensions_len = hello.u16()? as usize;
    let mut extensions = Reader::new(hello.take(extensions_len)?);

    while !extensions.is_empty() {
        let ext_type = extensions.u16()?;
        let ext_len = extensions.u16()? as usize;
        let body = extensions.take(ext_len)?;
        if ext_type == EXT_SERVER_NAME {
            return host_name(body);
        }
    }
    Err(TlsError::NoServerName)
}

/// Lit la liste `server_name_list` et rend le premier nom d'hôte.
fn host_name(extension: &[u8]) -> Result<String, TlsError> {
    let mut reader = Reader::new(extension);
    let list_len = reader.u16()? as usize;
    let mut list = Reader::new(reader.take(list_len)?);

    while !list.is_empty() {
        let name_type = list.u8()?;
        let len = list.u16()? as usize;
        let value = list.take(len)?;
        if name_type == NAME_TYPE_HOST {
            if value.is_empty() {
                return Err(TlsError::Malformed);
            }
            return Ok(name::escape(value));
        }
    }
    Err(TlsError::NoServerName)
}

/// Curseur de lecture sur des octets non fiables.
///
/// Toute lecture qui dépasse la fin rend [`TlsError::Incomplete`] plutôt que
/// de paniquer : c'est le seul point du parseur qui indexe les données.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], TlsError> {
        let end = self.pos.checked_add(len).ok_or(TlsError::Malformed)?;
        let slice = self.data.get(self.pos..end).ok_or(TlsError::Incomplete)?;
        self.pos = end;
        Ok(slice)
    }

    fn skip(&mut self, len: usize) -> Result<(), TlsError> {
        self.take(len).map(|_| ())
    }

    fn u8(&mut self) -> Result<u8, TlsError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TlsError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Result<usize, TlsError> {
        let bytes = self.take(3)?;
        Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
    }
}

/// Fabrication de ClientHello pour les tests.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Construit un ClientHello minimal annonçant `sni`.
    pub fn client_hello(sni: &str) -> Vec<u8> {
        let mut list = vec![NAME_TYPE_HOST];
        list.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        list.extend_from_slice(sni.as_bytes());

        let mut body = (list.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(&list);
        with_extension(EXT_SERVER_NAME, &body)
    }

    /// Un ClientHello dont la seule extension est du remplissage.
    pub fn client_hello_without_sni() -> Vec<u8> {
        with_extension(0x0015, &[0x00, 0x00]) // extension « padding »
    }

    /// Construit un ClientHello portant une unique extension.
    fn with_extension(ext_type: u16, ext_body: &[u8]) -> Vec<u8> {
        let mut extensions = ext_type.to_be_bytes().to_vec();
        extensions.extend_from_slice(&(ext_body.len() as u16).to_be_bytes());
        extensions.extend_from_slice(ext_body);

        let mut hello = vec![0x03, 0x03]; // version annoncée : TLS 1.2
        hello.extend_from_slice(&[0x00; 32]); // aléa
        hello.push(0x00); // pas de session
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // une suite
        hello.extend_from_slice(&[0x01, 0x00]); // compression : nulle
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        let len = hello.len();
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&hello);

        let mut record = vec![RECORD_HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}

#[cfg(test)]
mod tests {
    use super::testing::client_hello;
    use super::*;

    #[test]
    fn reads_the_server_name() {
        assert_eq!(
            server_name(&client_hello("api.github.com")).unwrap(),
            "api.github.com"
        );
    }

    #[test]
    fn a_split_client_hello_asks_for_more() {
        let hello = client_hello("github.com");
        // Un ClientHello coupé en deux par la MTU : chaque préfixe doit
        // demander la suite, jamais rendre un nom tronqué ni paniquer.
        for len in 1..hello.len() {
            assert_eq!(
                server_name(&hello[..len]),
                Err(TlsError::Incomplete),
                "préfixe de {len} octets"
            );
        }
    }

    #[test]
    fn rejects_what_is_not_a_client_hello() {
        assert_eq!(server_name(b""), Err(TlsError::Incomplete));
        assert_eq!(
            server_name(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]),
            Err(TlsError::NotAClientHello),
            "un record de données applicatives"
        );

        let mut server_hello = client_hello("example.com");
        server_hello[5] = 0x02; // ServerHello
        assert_eq!(server_name(&server_hello), Err(TlsError::NotAClientHello));
    }

    #[test]
    fn a_client_hello_without_sni_is_reported_as_such() {
        let hello = super::testing::client_hello_without_sni();
        assert_eq!(server_name(&hello), Err(TlsError::NoServerName));
    }

    #[test]
    fn a_lying_length_field_cannot_read_past_the_end() {
        let mut hello = client_hello("example.com");
        hello[3] = 0xFF; // le record annonce 65 xxx octets
        hello[4] = 0xFF;
        assert_eq!(server_name(&hello), Err(TlsError::Incomplete));
    }

    #[test]
    fn control_bytes_in_the_name_are_escaped() {
        let hello = client_hello("a\u{1b}b.com");
        let name = server_name(&hello).unwrap();
        assert_eq!(name, "a\\027b.com");
        assert!(!name.contains('\u{1b}'));
    }
}
