//! Le relais DNS : on écoute, on tranche, on transmet ou on nie.
//!
//! Le serveur écoute en UDP sur l'adresse du tunnel. Pour chaque question,
//! [`Policy`] dit si le nom est autorisé : sinon le client reçoit un NXDOMAIN
//! et la question ne sort jamais du tunnel.
//!
//! La décision est prise dans la boucle de réception — Redis est local, une
//! consultation coûte moins qu'un changement de thread. Le relais vers
//! l'amont, lui, attend le réseau : il est confié à quelques threads, sans
//! quoi une question lente retiendrait toutes les suivantes.

use std::convert::Infallible;
use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{sync_channel, Receiver, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::dns::message;

use super::policy::Policy;

/// Port du service DNS.
pub const DNS_PORT: u16 = 53;
/// Résolveur interrogé pour les noms autorisés.
///
/// Un résolveur public, et non celui du système : sur la machine qui héberge
/// le tunnel, `/etc/resolv.conf` peut très bien pointer vers nous — la
/// question tournerait en rond.
pub const DEFAULT_UPSTREAM: &str = "1.1.1.1:53";
/// Temps laissé à l'amont pour répondre.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
/// Relais menés de front.
pub const DEFAULT_WORKERS: usize = 4;
/// Questions en attente de relais tolérées avant d'en jeter.
pub const DEFAULT_QUEUE: usize = 256;
/// Taille du tampon de réception.
///
/// 512 octets suffisent au DNS d'origine ; EDNS0 permet davantage, et 4096
/// est la taille que les clients annoncent le plus souvent.
const MAX_DATAGRAM: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error(
        "écoute impossible sur {addr}: {source} — l'interface porte-t-elle \
         cette adresse, et le port 53 est-il libre (root requis) ?"
    )]
    Bind {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("relais vers {upstream} impossible: {source}")]
    Upstream {
        upstream: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("thread de relais impossible à créer: {0}")]
    Spawn(#[source] io::Error),
    #[error("réception interrompue: {0}")]
    Recv(#[source] io::Error),
}

/// Où écouter, et à qui transmettre.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Adresse d'écoute — l'IP du tunnel, port 53.
    pub bind: SocketAddr,
    /// Résolveur amont interrogé pour les noms autorisés.
    pub upstream: SocketAddr,
    /// Temps laissé à l'amont avant d'abandonner une question.
    pub timeout: Duration,
    /// Relais menés de front.
    pub workers: usize,
    /// Questions en attente de relais avant d'en jeter.
    pub queue: usize,
    /// Écrit une ligne par question refusée sur stdout.
    pub verbose: bool,
}

impl DnsConfig {
    /// Réglages par défaut pour une adresse d'écoute donnée.
    pub fn new(bind: SocketAddr) -> Self {
        Self {
            bind,
            upstream: DEFAULT_UPSTREAM
                .parse()
                .expect("DEFAULT_UPSTREAM est une adresse littérale"),
            timeout: DEFAULT_TIMEOUT,
            workers: DEFAULT_WORKERS,
            queue: DEFAULT_QUEUE,
            verbose: true,
        }
    }
}

/// Une question autorisée, en attente d'être posée à l'amont.
struct Relay {
    request: Vec<u8>,
    client: SocketAddr,
}

/// Sert les questions jusqu'à erreur fatale.
///
/// Le type de succès est [`Infallible`] : cette boucle ne s'arrête pas
/// d'elle-même.
pub fn serve(cfg: &DnsConfig, mut policy: Policy) -> Result<Infallible, DnsError> {
    let socket = UdpSocket::bind(cfg.bind).map_err(|source| DnsError::Bind {
        addr: cfg.bind,
        source,
    })?;

    let (tx, rx) = sync_channel::<Relay>(cfg.queue.max(1));
    spawn_relays(cfg, &socket, rx)?;

    eprintln!(
        "[dns] écoute sur {} — amont {}, {} relais",
        cfg.bind, cfg.upstream, cfg.workers
    );

    let mut buffer = [0u8; MAX_DATAGRAM];
    loop {
        let (len, client) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            // Un ICMP « port unreachable » revient au socket sous forme
            // d'erreur : il concerne un datagramme déjà parti, pas l'écoute.
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(DnsError::Recv(e)),
        };
        let request = &buffer[..len];

        // Ni une requête, ni un paquet lisible : le silence est la réponse.
        // Un client qui parle mal n'obtient rien à quoi s'accrocher.
        let Ok(query) = message::parse_query(request) else {
            continue;
        };

        let decision = policy.decide(&query.name);
        if decision.denied() {
            deny(
                &socket,
                request,
                client,
                cfg.verbose,
                &query.name,
                &decision,
            );
            continue;
        }

        // File pleine : l'amont ne suit pas. Jeter est ce que fait déjà le
        // réseau, et le client réémettra — mieux vaut cela que retenir la
        // boucle de réception.
        match tx.try_send(Relay {
            request: request.to_vec(),
            client,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                eprintln!("[dns] file pleine — {} abandonné", query.name)
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(DnsError::Recv(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "plus aucun relais en vie",
                )))
            }
        }
    }
}

/// Renvoie « ce nom n'existe pas » au client, et le note.
fn deny(
    socket: &UdpSocket,
    request: &[u8],
    client: SocketAddr,
    verbose: bool,
    name: &str,
    decision: &super::policy::Decision,
) {
    if let Some(response) = message::nxdomain(request) {
        let _ = socket.send_to(&response, client);
    }
    if !verbose {
        return;
    }
    let rule = decision.matched.as_deref().unwrap_or(name);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    // Sortie redirigée vers un fichier ou un pipe : sans vidage explicite, les
    // lignes resteraient dans le tampon.
    if writeln!(out, "NXDOMAIN {name} ({client}) — règle: {rule}").is_ok() {
        let _ = out.flush();
    }
}

/// Lance les threads de relais, chacun avec son socket vers l'amont.
fn spawn_relays(cfg: &DnsConfig, socket: &UdpSocket, rx: Receiver<Relay>) -> Result<(), DnsError> {
    let rx = Arc::new(Mutex::new(rx));
    for n in 0..cfg.workers.max(1) {
        let upstream = open_upstream(cfg)?;
        // Le même socket sert à répondre : le client attend la réponse de
        // l'adresse et du port auxquels il a posé sa question.
        let back = socket.try_clone().map_err(DnsError::Recv)?;
        let rx = Arc::clone(&rx);
        let cfg = cfg.clone();
        thread::Builder::new()
            .name(format!("dns-relay-{n}"))
            .spawn(move || relay_loop(&cfg, upstream, back, rx))
            .map_err(DnsError::Spawn)?;
    }
    Ok(())
}

/// Socket vers l'amont, connecté et borné dans le temps.
///
/// `connect` fixe le correspondant : le noyau écarte alors les datagrammes
/// venus d'ailleurs, ce qui retire à un tiers la possibilité de répondre à
/// notre place.
fn open_upstream(cfg: &DnsConfig) -> Result<UdpSocket, DnsError> {
    let bind: SocketAddr = if cfg.upstream.is_ipv6() {
        "[::]:0".parse().expect("adresse littérale")
    } else {
        "0.0.0.0:0".parse().expect("adresse littérale")
    };
    let socket = UdpSocket::bind(bind).and_then(|socket| {
        socket.connect(cfg.upstream)?;
        socket.set_read_timeout(Some(cfg.timeout))?;
        Ok(socket)
    });
    socket.map_err(|source| DnsError::Upstream {
        upstream: cfg.upstream,
        source,
    })
}

/// Pose les questions autorisées à l'amont et rend ses réponses au client.
fn relay_loop(
    cfg: &DnsConfig,
    upstream: UdpSocket,
    back: UdpSocket,
    rx: Arc<Mutex<Receiver<Relay>>>,
) {
    let mut buffer = [0u8; MAX_DATAGRAM];
    loop {
        // Le verrou n'est tenu que le temps de prendre une question : deux
        // relais ne s'attendent pas pendant leur aller-retour réseau.
        let job = {
            let rx = match rx.lock() {
                Ok(rx) => rx,
                // Un relais a paniqué en tenant le verrou : les autres
                // s'arrêtent plutôt que de tourner sur un état inconnu.
                Err(_) => return,
            };
            rx.recv()
        };
        let Ok(job) = job else {
            return; // la boucle de réception s'est arrêtée
        };

        match forward(cfg, &upstream, &job, &mut buffer) {
            Ok(len) => {
                let _ = back.send_to(&buffer[..len], job.client);
            }
            // Amont muet ou injoignable : on ne fabrique rien à la place. Le
            // client réémettra, et ses réglages diront quand renoncer.
            Err(e) => eprintln!("[dns] amont {} sans réponse: {e}", cfg.upstream),
        }
    }
}

/// Un aller-retour vers l'amont ; rend la longueur de la réponse retenue.
fn forward(
    cfg: &DnsConfig,
    upstream: &UdpSocket,
    job: &Relay,
    buffer: &mut [u8; MAX_DATAGRAM],
) -> io::Result<usize> {
    upstream.send(&job.request)?;

    let expected = message::id(&job.request);
    let deadline = std::time::Instant::now() + cfg.timeout;
    loop {
        let len = upstream.recv(buffer)?;
        // Une réponse dont l'identifiant ne correspond pas est celle d'une
        // question abandonnée, ou une tentative d'empoisonnement : on la
        // laisse tomber et on continue d'attendre la nôtre.
        if message::id(&buffer[..len]) == expected {
            return Ok(len);
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "aucune réponse à la question posée",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::message::testing::query;

    /// Un faux résolveur amont : il répond à tout par la requête retournée.
    fn upstream_echo() -> (SocketAddr, thread::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buffer = [0u8; MAX_DATAGRAM];
            let (len, from) = socket.recv_from(&mut buffer).unwrap();
            let mut answer = buffer[..len].to_vec();
            answer[2] |= 0x80; // QR = 1
            socket.send_to(&answer, from).unwrap();
        });
        (addr, handle)
    }

    #[test]
    fn an_answer_meant_for_another_question_is_not_relayed() {
        let (upstream_addr, _server) = upstream_echo();
        let mut cfg = DnsConfig::new("127.0.0.1:0".parse().unwrap());
        cfg.upstream = upstream_addr;
        cfg.timeout = Duration::from_millis(200);

        let upstream = open_upstream(&cfg).unwrap();
        let job = Relay {
            request: query(0x1234, "crates.io"),
            client: "127.0.0.1:9".parse().unwrap(),
        };
        let mut buffer = [0u8; MAX_DATAGRAM];
        let len = forward(&cfg, &upstream, &job, &mut buffer).unwrap();
        assert_eq!(message::id(&buffer[..len]), Some(0x1234));
    }

    #[test]
    fn a_silent_upstream_ends_in_a_timeout_not_a_wait_forever() {
        // Une adresse qui n'écoute pas : personne ne répondra.
        let mut cfg = DnsConfig::new("127.0.0.1:0".parse().unwrap());
        cfg.upstream = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        cfg.timeout = Duration::from_millis(100);

        let upstream = open_upstream(&cfg).unwrap();
        let job = Relay {
            request: query(1, "crates.io"),
            client: "127.0.0.1:9".parse().unwrap(),
        };
        let mut buffer = [0u8; MAX_DATAGRAM];
        assert!(forward(&cfg, &upstream, &job, &mut buffer).is_err());
    }
}
