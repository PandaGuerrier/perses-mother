//! Le relais DNS de bout en bout, sur la boucle locale.
//!
//! Un faux résolveur amont, un vrai Redis, et un client qui pose ses
//! questions en UDP : ce que voit un pair du tunnel, à l'adresse près.
//! Lancer Redis avec `docker compose up -d redis` ; sans lui, ces tests
//! s'annoncent ignorés plutôt que d'échouer.

use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use perses_mother::cache::{Cache, CacheConfig};
use perses_mother::dns::{self, DnsConfig, Policy};

/// Lit le `.env` du dépôt, que `compose.yaml` utilise aussi.
fn env_file_password() -> Option<String> {
    let content = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/.env")).ok()?;
    content.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "REDIS_PASSWORD").then(|| value.trim().to_string())
    })
}

/// Ouvre une connexion, ou rend `None` si Redis n'est pas joignable.
fn cache(namespace: &str) -> Option<Cache> {
    let config = CacheConfig {
        password: env_file_password(),
        namespace: format!("perses-test:{namespace}"),
        ..CacheConfig::default()
    };
    match Cache::connect(config) {
        Ok(cache) => Some(cache),
        Err(e) => {
            if env_file_password().is_some() {
                panic!(
                    "Redis injoignable alors que .env existe ({e})\n\
                     lancer `docker compose up -d redis`"
                );
            }
            eprintln!("test ignoré — pas de .env, Redis non configuré ({e})");
            None
        }
    }
}

/// Requête A minimale pour `name`, telle qu'un client l'émettrait.
fn query(id: u16, name: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00]); // requête récursive
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    packet.extend_from_slice(&[0x00; 6]); // AN/NS/AR = 0
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE = A, QCLASS = IN
    packet
}

/// Faux résolveur amont : il répond à tout, en retournant la question.
///
/// Sa réponse est reconnaissable à son AA — c'est ce qui permet de dire, plus
/// bas, si le relais est allé la chercher ou s'il a répondu tout seul.
fn upstream() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut buffer = [0u8; 2048];
        while let Ok((len, from)) = socket.recv_from(&mut buffer) {
            let mut answer = buffer[..len].to_vec();
            answer[2] |= 0x84; // QR = 1, AA = 1
            let _ = socket.send_to(&answer, from);
        }
    });
    addr
}

/// Adresse libre sur la boucle locale, que le serveur reprendra.
fn free_port() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Lance un relais servi par `cache`, et rend son adresse.
fn serve(cache: Cache) -> SocketAddr {
    let bind = free_port();
    let mut cfg = DnsConfig::new(bind);
    cfg.upstream = upstream();
    cfg.timeout = Duration::from_secs(1);
    cfg.workers = 2;
    cfg.verbose = false;

    // Sans mémoire des décisions : les marquages posés par le test valent
    // immédiatement.
    let policy = Policy::new(cache).with_ttl(Duration::ZERO);
    thread::spawn(move || match dns::serve(&cfg, policy) {
        Ok(never) => match never {},
        Err(e) => eprintln!("relais arrêté: {e}"),
    });

    // L'écoute est ouverte dans le thread : on laisse le temps au `bind`.
    thread::sleep(Duration::from_millis(200));
    bind
}

/// Pose une question et rend la réponse, ou `None` après une seconde.
fn ask(server: SocketAddr, packet: &[u8]) -> Option<Vec<u8>> {
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client.send_to(packet, server).unwrap();
    let mut buffer = [0u8; 2048];
    let (len, _) = client.recv_from(&mut buffer).ok()?;
    Some(buffer[..len].to_vec())
}

fn rcode(response: &[u8]) -> u16 {
    u16::from_be_bytes([response[2], response[3]]) & 0x000F
}

/// Vrai si la réponse vient du faux amont — lui seul pose AA.
fn from_upstream(response: &[u8]) -> bool {
    u16::from_be_bytes([response[2], response[3]]) & 0x0400 != 0
}

macro_rules! cache_or_skip {
    ($namespace:expr) => {
        match cache($namespace) {
            Some(cache) => cache,
            None => return,
        }
    };
}

#[test]
fn a_marked_name_is_denied_and_never_reaches_the_upstream() {
    let mut cache = cache_or_skip!("dns-relay");
    cache.delete("crates.io").ok();
    cache.set("chatgpt.com", "true").unwrap();

    let server = serve(cache);

    // Le nom marqué, et un sous-domaine que personne n'a marqué.
    for (id, name) in [(0x1111, "chatgpt.com"), (0x2222, "ws.chatgpt.com")] {
        let response = ask(server, &query(id, name)).expect("le relais doit répondre");
        assert_eq!(
            u16::from_be_bytes([response[0], response[1]]),
            id,
            "{name}: la réponse doit porter l'identifiant de la question"
        );
        assert_eq!(rcode(&response), 3, "{name}: NXDOMAIN attendu");
        assert!(
            !from_upstream(&response),
            "{name}: la question n'aurait pas dû sortir du tunnel"
        );
        assert_eq!(
            &response[12..],
            &query(id, name)[12..],
            "{name}: la question doit revenir telle quelle"
        );
    }

    // Un nom que rien ne marque : la réponse vient bien de l'amont.
    let response = ask(server, &query(0x3333, "crates.io")).expect("le relais doit répondre");
    assert_eq!(rcode(&response), 0);
    assert!(from_upstream(&response), "la question devait être relayée");

    let mut cache = cache_or_skip!("dns-relay");
    cache.delete("chatgpt.com").ok();
}

#[test]
fn a_packet_that_is_not_a_query_gets_no_answer() {
    let cache = cache_or_skip!("dns-noise");
    let server = serve(cache);

    // Trop court, puis une réponse au lieu d'une question : dans les deux cas
    // le relais se tait, plutôt que de donner prise.
    assert_eq!(ask(server, b"\xff\xff"), None);
    let mut response = query(1, "crates.io");
    response[2] |= 0x80;
    assert_eq!(ask(server, &response), None);
}
