//! La décision : résoudre le nom, ou nier son existence.
//!
//! Ce module ne touche pas au réseau — il reçoit un nom et rend un verdict.
//! La source de vérité est la même que celle du sniffer et du filtre : Redis.
//! Un nom y est marqué de deux façons, toutes deux honorées ici :
//!
//! * une clé à son nom (`perses:chatgpt.com`), ce que pose le sniffer ;
//! * une appartenance à l'ensemble [`BLACKLIST_SET`], ce que consulte le
//!   filtre NFQUEUE.
//!
//! Un nom marqué couvre ses sous-domaines : `chatgpt.com` suffit à nier
//! `ws.chatgpt.com`, sans avoir à les énumérer.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::cache::Cache;
use crate::filter::BLACKLIST_SET;

/// Durée pendant laquelle une décision est réutilisée sans redemander à Redis.
///
/// Un client répète la même question des dizaines de fois par minute ; sans
/// cette mémoire, chaque requête coûterait un aller-retour par suffixe.
pub const DEFAULT_TTL: Duration = Duration::from_secs(30);
/// Décisions gardées en mémoire avant de repartir d'une table vide.
const MAX_MEMO: usize = 4096;
/// Suffixes consultés pour un nom, le nom complet compris.
///
/// Borne le coût d'un nom à mille labels : au-delà, ce n'est plus une
/// hiérarchie de domaines mais une façon de nous faire travailler.
const MAX_SUFFIXES: usize = 8;

/// Ce qu'on fait d'une question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// La question part vers le résolveur amont.
    Resolve,
    /// Le client reçoit un NXDOMAIN, la question ne sort pas du tunnel.
    Deny,
}

/// Ce qui a été décidé, et pourquoi — de quoi journaliser sans deviner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    /// Nom marqué qui a provoqué le refus : le nom demandé, ou l'un de ses
    /// parents. `None` quand la question passe.
    pub matched: Option<String>,
}

impl Decision {
    fn resolve() -> Self {
        Self {
            verdict: Verdict::Resolve,
            matched: None,
        }
    }

    fn deny(rule: String) -> Self {
        Self {
            verdict: Verdict::Deny,
            matched: Some(rule),
        }
    }

    /// Vrai si la question a été refusée.
    pub fn denied(&self) -> bool {
        self.verdict == Verdict::Deny
    }
}

/// Applique les marquages du cache aux noms demandés.
pub struct Policy {
    cache: Cache,
    /// Nom demandé → (règle qui le nie, date de la décision). `None` en
    /// première place vaut « autorisé ».
    memo: HashMap<String, (Option<String>, Instant)>,
    ttl: Duration,
}

impl Policy {
    pub fn new(cache: Cache) -> Self {
        Self {
            cache,
            memo: HashMap::new(),
            ttl: DEFAULT_TTL,
        }
    }

    /// Change la durée de vie des décisions mémorisées.
    ///
    /// Une durée nulle interroge Redis à chaque question : c'est ce que font
    /// les tests, pour voir un marquage prendre effet immédiatement.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Décisions actuellement mémorisées.
    pub fn memoized(&self) -> usize {
        self.memo.len()
    }

    /// Tranche du sort d'un nom.
    pub fn decide(&mut self, name: &str) -> Decision {
        // Les noms sont insensibles à la casse : `ChatGPT.com` et
        // `chatgpt.com` sont le même nom, et le cache n'en connaît qu'une
        // écriture.
        let name = name.to_ascii_lowercase();

        if let Some((rule, at)) = self.memo.get(&name) {
            if at.elapsed() < self.ttl {
                return match rule {
                    Some(rule) => Decision::deny(rule.clone()),
                    None => Decision::resolve(),
                };
            }
        }

        let rule = self.lookup(&name);
        self.remember(name, rule.clone());
        match rule {
            Some(rule) => Decision::deny(rule),
            None => Decision::resolve(),
        }
    }

    /// Cherche, du nom vers la racine, le premier suffixe marqué.
    fn lookup(&mut self, name: &str) -> Option<String> {
        for candidate in suffixes(name) {
            if self.is_marked(candidate) {
                return Some(candidate.to_string());
            }
        }
        None
    }

    /// Consulte les deux marquages du cache.
    ///
    /// Redis injoignable : on laisse résoudre. Nier tous les noms du tunnel
    /// parce qu'une base de données a redémarré couperait Internet aux
    /// clients, ce qui est pire que le mal — même choix que
    /// [`crate::filter::Policy`].
    fn is_marked(&mut self, candidate: &str) -> bool {
        match self.cache.exists(candidate) {
            Ok(true) => return true,
            Ok(false) => {}
            Err(e) => {
                eprintln!("[dns] cache injoignable, {candidate} laissé passer: {e}");
                return false;
            }
        }
        match self.cache.set_contains(BLACKLIST_SET, candidate) {
            Ok(found) => found,
            Err(e) => {
                eprintln!("[dns] liste noire inaccessible, {candidate} laissé passer: {e}");
                false
            }
        }
    }

    fn remember(&mut self, name: String, rule: Option<String>) {
        // Personne ne nous dira qu'un nom ne sera plus demandé : on borne,
        // quitte à tout oublier d'un coup. Au pire, les questions suivantes
        // repartent vers Redis.
        if self.memo.len() >= MAX_MEMO {
            self.memo.clear();
        }
        self.memo.insert(name, (rule, Instant::now()));
    }
}

/// Le nom, puis chacun de ses parents : `a.b.com` → `a.b.com`, `b.com`, `com`.
///
/// Un nom qui a traversé l'échappement de [`crate::name`] contient une
/// contre-oblique : ses points ne sont plus des frontières de labels fiables,
/// et on ne remonte pas ses parents — il est consulté tel quel.
fn suffixes(name: &str) -> impl Iterator<Item = &str> {
    let escaped = name.contains('\\');
    std::iter::once(name)
        .chain(
            name.match_indices('.')
                .filter(move |_| !escaped)
                .map(|(at, _)| &name[at + 1..]),
        )
        .filter(|candidate| !candidate.is_empty())
        .take(MAX_SUFFIXES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheConfig;

    #[test]
    fn walks_up_from_the_name_to_its_parents() {
        assert_eq!(
            suffixes("ws.chatgpt.com").collect::<Vec<_>>(),
            ["ws.chatgpt.com", "chatgpt.com", "com"]
        );
        assert_eq!(suffixes("com").collect::<Vec<_>>(), ["com"]);
        // La racine, et un nom terminé par un point : pas de suffixe vide.
        assert_eq!(suffixes(".").collect::<Vec<_>>(), ["."]);
        assert_eq!(
            suffixes("chatgpt.com.").collect::<Vec<_>>(),
            ["chatgpt.com.", "com."]
        );
    }

    #[test]
    fn a_thousand_labels_do_not_make_a_thousand_lookups() {
        let long = "a.".repeat(500) + "example";
        assert!(suffixes(&long).count() <= MAX_SUFFIXES);
    }

    #[test]
    fn an_escaped_name_is_only_looked_up_whole() {
        // Le point de ce label est échappé : ce n'est pas une frontière, et
        // `com` n'est pas son parent.
        assert_eq!(
            suffixes("evil\\.chatgpt.com").collect::<Vec<_>>(),
            ["evil\\.chatgpt.com"]
        );
    }

    /// Rend une politique branchée sur Redis, ou `None` s'il est absent.
    fn policy(namespace: &str) -> Option<Policy> {
        let config = CacheConfig {
            password: test_password(),
            namespace: format!("perses-test:{namespace}"),
            ..CacheConfig::default()
        };
        match Cache::connect(config) {
            // Sans mémoire : un marquage posé par le test doit se voir tout
            // de suite.
            Ok(cache) => Some(Policy::new(cache).with_ttl(Duration::ZERO)),
            Err(e) => {
                assert!(
                    test_password().is_none(),
                    "Redis injoignable alors que .env existe ({e}) — \
                     lancer `docker compose up -d redis`"
                );
                eprintln!("test ignoré — pas de .env, Redis non configuré");
                None
            }
        }
    }

    fn test_password() -> Option<String> {
        let env = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/.env")).ok()?;
        env.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "REDIS_PASSWORD").then(|| value.trim().to_string())
        })
    }

    macro_rules! policy_or_skip {
        ($ns:expr) => {
            match policy($ns) {
                Some(policy) => policy,
                None => return,
            }
        };
    }

    #[test]
    fn resolves_a_name_nobody_marked() {
        let mut policy = policy_or_skip!("dns-allow");
        policy.cache.delete("crates.io").ok();
        policy.cache.delete(BLACKLIST_SET).ok();

        let decision = policy.decide("crates.io");
        assert_eq!(decision.verdict, Verdict::Resolve);
        assert_eq!(decision.matched, None);
    }

    #[test]
    fn denies_a_name_the_sniffer_marked_and_all_below_it() {
        let mut policy = policy_or_skip!("dns-deny");
        policy.cache.delete(BLACKLIST_SET).ok();
        policy.cache.set("chatgpt.com", "true").unwrap();

        assert!(policy.decide("chatgpt.com").denied());

        // Un sous-domaine jamais marqué : nié par son parent.
        let decision = policy.decide("ws.chatgpt.com");
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.matched.as_deref(), Some("chatgpt.com"));

        // La casse ne protège de rien.
        assert!(policy.decide("WS.ChatGPT.COM").denied());

        // Un voisin qui finit pareil sans être un sous-domaine passe.
        assert!(!policy.decide("notchatgpt.com").denied());

        policy.cache.delete("chatgpt.com").ok();
    }

    #[test]
    fn denies_a_name_the_blacklist_holds() {
        let mut policy = policy_or_skip!("dns-blacklist");
        policy.cache.delete("interdit.example").ok();
        policy.cache.delete(BLACKLIST_SET).ok();
        policy
            .cache
            .add_to_set(BLACKLIST_SET, "interdit.example")
            .unwrap();

        let decision = policy.decide("cdn.interdit.example");
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.matched.as_deref(), Some("interdit.example"));

        policy.cache.delete(BLACKLIST_SET).ok();
    }

    #[test]
    fn a_decision_is_not_asked_twice() {
        let mut policy = policy_or_skip!("dns-memo");
        policy.cache.delete("chatgpt.com").ok();
        policy.cache.delete(BLACKLIST_SET).ok();
        policy.ttl = DEFAULT_TTL;

        assert!(!policy.decide("chatgpt.com").denied());
        // Marqué après coup : la décision mémorisée tient jusqu'à son terme.
        policy.cache.set("chatgpt.com", "true").unwrap();
        assert!(!policy.decide("chatgpt.com").denied());
        assert_eq!(policy.memoized(), 1);

        policy.cache.delete("chatgpt.com").ok();
    }

    #[test]
    fn the_memory_stays_bounded() {
        let mut policy = policy_or_skip!("dns-bounded");
        policy.ttl = DEFAULT_TTL;
        for n in 0..(MAX_MEMO + 50) {
            policy.decide(&format!("h{n}"));
        }
        assert!(policy.memoized() <= MAX_MEMO);
    }
}
