//! Écriture de JSON, réduite à ce qu'un corps de requête demande.
//!
//! Le projet n'embarque pas de sérialiseur : les corps envoyés ici sont des
//! objets plats de chaînes et de nombres, et les construire à la main coûte
//! moins qu'une dépendance de plus. Tout passe par [`Object`], donc tout est
//! échappé — aucune valeur venue du réseau n'atteint la sortie telle quelle.

use std::fmt::Display;

/// Un objet JSON en cours d'écriture.
#[derive(Debug)]
pub struct Object {
    buf: String,
}

impl Object {
    pub fn new() -> Self {
        Self {
            buf: String::from("{"),
        }
    }

    /// Une chaîne, échappée.
    pub fn string(&mut self, key: &str, value: &str) -> &mut Self {
        self.key(key);
        escape_into(value, &mut self.buf);
        self
    }

    /// Une chaîne, ou `null` si elle est absente.
    pub fn maybe_string(&mut self, key: &str, value: Option<&str>) -> &mut Self {
        match value {
            Some(value) => self.string(key, value),
            None => self.null(key),
        }
    }

    /// Un nombre, écrit tel que son `Display` le rend.
    pub fn number(&mut self, key: &str, value: impl Display) -> &mut Self {
        self.key(key);
        self.buf.push_str(&value.to_string());
        self
    }

    /// Un nombre, ou `null` s'il est absent.
    pub fn maybe_number(&mut self, key: &str, value: Option<impl Display>) -> &mut Self {
        match value {
            Some(value) => self.number(key, value),
            None => self.null(key),
        }
    }

    pub fn boolean(&mut self, key: &str, value: bool) -> &mut Self {
        self.key(key);
        self.buf.push_str(if value { "true" } else { "false" });
        self
    }

    /// Un tableau de chaînes.
    pub fn strings(&mut self, key: &str, values: &[String]) -> &mut Self {
        self.key(key);
        self.buf.push('[');
        for (i, value) in values.iter().enumerate() {
            if i > 0 {
                self.buf.push(',');
            }
            escape_into(value, &mut self.buf);
        }
        self.buf.push(']');
        self
    }

    /// Un objet imbriqué.
    pub fn object(&mut self, key: &str, value: Object) -> &mut Self {
        self.key(key);
        self.buf.push_str(&value.finish());
        self
    }

    pub fn null(&mut self, key: &str) -> &mut Self {
        self.key(key);
        self.buf.push_str("null");
        self
    }

    /// Ferme l'objet et rend le texte JSON.
    pub fn finish(mut self) -> String {
        self.buf.push('}');
        self.buf
    }

    /// Écrit la clé suivie de son deux-points, précédée d'une virgule s'il y
    /// a déjà un champ.
    fn key(&mut self, key: &str) {
        if self.buf.len() > 1 {
            self.buf.push(',');
        }
        escape_into(key, &mut self.buf);
        self.buf.push(':');
    }
}

impl Default for Object {
    fn default() -> Self {
        Self::new()
    }
}

/// Écrit `value` entre guillemets, échappée selon la RFC 8259.
fn escape_into(value: &str, out: &mut String) {
    use std::fmt::Write as _;
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Les autres caractères de contrôle n'ont pas d'abréviation.
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_a_flat_object() {
        let mut object = Object::new();
        object
            .string("domain", "ads.example.com")
            .boolean("blocked", true)
            .number("observed_at", 1757030400u64);
        assert_eq!(
            object.finish(),
            r#"{"domain":"ads.example.com","blocked":true,"observed_at":1757030400}"#
        );
    }

    #[test]
    fn an_empty_object_is_still_valid_json() {
        assert_eq!(Object::new().finish(), "{}");
    }

    #[test]
    fn nests_objects_and_arrays() {
        let mut peer = Object::new();
        peer.string("public_key", "abc=")
            .strings("allowed_ips", &["10.8.0.2/32".to_string()]);
        let mut root = Object::new();
        root.object("client", peer).maybe_string("endpoint", None);
        assert_eq!(
            root.finish(),
            r#"{"client":{"public_key":"abc=","allowed_ips":["10.8.0.2/32"]},"endpoint":null}"#
        );
    }

    #[test]
    fn escapes_anything_that_would_break_out_of_a_string() {
        let mut object = Object::new();
        object.string("domain", "a\"b\\c\nd\u{1}");
        let expected = concat!(r#"{"domain":"a\"b\\c\nd"#, r#"\u0001"}"#);
        assert_eq!(object.finish(), expected);
    }

    #[test]
    fn escapes_keys_too() {
        let mut object = Object::new();
        object.number("a\"b", 1);
        assert_eq!(object.finish(), r#"{"a\"b":1}"#);
    }
}
