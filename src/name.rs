//! Affichage sûr d'un nom venu du réseau.
//!
//! Ces octets sont choisis par un tiers et finissent dans un terminal : sans
//! échappement, un client hostile pourrait y glisser des séquences ANSI qui
//! effacent des lignes ou colorent la sortie.

/// Rend une version imprimable de `bytes`, façon RFC 1035.
pub fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    escape_into(bytes, &mut out);
    out
}

/// Comme [`escape`], en écrivant à la suite d'une chaîne existante.
pub fn escape_into(bytes: &[u8], out: &mut String) {
    use std::fmt::Write as _;
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            0x21..=0x7E => out.push(b as char),
            _ => {
                let _ = write!(out, "\\{b:03}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_ordinary_host_names_intact() {
        assert_eq!(escape(b"api.github.com"), "api.github.com");
        assert_eq!(escape(b"xn--80ak6aa92e.com"), "xn--80ak6aa92e.com");
    }

    #[test]
    fn escapes_anything_a_terminal_would_interpret() {
        assert_eq!(escape(b"\x1b[2Kevil"), "\\027[2Kevil");
        assert_eq!(escape(b"a b"), "a\\032b");
        assert_eq!(escape(b"a\\b"), "a\\\\b");
        assert_eq!(escape(b"\n"), "\\010");
        assert_eq!(escape("café".as_bytes()), "caf\\195\\169");
    }
}
