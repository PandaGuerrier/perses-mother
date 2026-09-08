//! Écriture des rapports, hors du chemin de la capture.
//!
//! La boucle de capture ne doit jamais attendre l'écriture : un fichier sur
//! un disque lent, ou une socket dont personne ne lit l'autre bout, c'est
//! autant de paquets manqués. Elle se contente donc de déposer une
//! observation dans une file bornée, et un thread dédié l'enrichit — clé
//! publique du pair, endpoint, compteurs — puis l'écrit. Si la file déborde,
//! on jette : perdre des rapports vaut mieux que perdre du trafic.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::wg::{self, DeviceStatus};

use super::config::ReportConfig;
use super::json::Object;

/// Ce que la capture transmet au rapporteur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Nom demandé, déjà échappé par [`crate::name`].
    pub domain: String,
    /// Adresse de l'émetteur dans le tunnel, qui désignera son pair.
    pub client: IpAddr,
    /// Horodatage Unix de l'observation, en secondes.
    pub observed_at: u64,
}

impl Observation {
    /// Observation datée de maintenant.
    pub fn now(domain: impl Into<String>, client: IpAddr) -> Self {
        Self {
            domain: domain.into(),
            client,
            observed_at: unix_time(),
        }
    }
}

/// Point de dépôt des observations à rapporter.
///
/// Peut être construit désactivé : `report` est alors sans effet, et rien
/// dans l'appelant n'a à le savoir.
pub struct Reporter {
    tx: Option<SyncSender<Observation>>,
    /// Rapports jetés faute de place, remis à zéro par le thread d'écriture
    /// quand il les signale.
    dropped: Arc<AtomicU64>,
}

impl Reporter {
    /// Rapporteur muet.
    pub fn disabled() -> Self {
        Self {
            tx: None,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Lit la configuration et démarre le thread d'écriture. `device` est le
    /// périphérique dont les pairs seront lus.
    pub fn from_env(device: &str) -> Self {
        Self::spawn(ReportConfig::from_env(), device)
    }

    /// Démarre le thread d'écriture pour une configuration donnée.
    pub fn spawn(cfg: ReportConfig, device: &str) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(cfg.queue);
        let dropped = Arc::new(AtomicU64::new(0));
        let device = device.to_string();
        eprintln!(
            "rapport: les domaines connus seront écrits dans {}",
            cfg.socket.display()
        );

        let counter = Arc::clone(&dropped);
        // Un thread détaché : il meurt avec le processus, comme la capture.
        std::thread::Builder::new()
            .name("reporter".to_string())
            .spawn(move || serve(cfg, device, rx, counter))
            .expect("le thread de rapport doit démarrer");

        Self {
            tx: Some(tx),
            dropped,
        }
    }

    /// Dit si les rapports partent vraiment.
    pub fn is_enabled(&self) -> bool {
        self.tx.is_some()
    }

    /// Dépose une observation. Ne bloque jamais.
    pub fn report(&self, observation: Observation) {
        let Some(tx) = &self.tx else {
            return;
        };
        match tx.try_send(observation) {
            Ok(()) => {}
            // La sortie est lente ou bouchée et la file s'est remplie. Le
            // thread d'écriture dira combien ont été perdus quand il repassera.
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            // Le thread d'écriture est mort : plus personne n'écoute.
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

/// Boucle du thread d'écriture.
fn serve(cfg: ReportConfig, device: String, rx: Receiver<Observation>, dropped: Arc<AtomicU64>) {
    let mut sink = Sink::new(cfg.socket);
    let mut peers = Peers::new(device, cfg.peers_ttl);

    for observation in rx {
        let lost = dropped.swap(0, Ordering::Relaxed);
        if lost > 0 {
            eprintln!("rapport: {lost} rapport(s) abandonné(s), file pleine");
        }

        let body = payload(&observation, peers.current());
        if let Err(err) = sink.write_line(&body) {
            eprintln!("rapport: {} non signalé — {err}", observation.domain);
        }
    }
}

/// Sortie des rapports : une ligne de JSON par observation.
///
/// Le chemin peut être une socket Unix — un collecteur écoute à l'autre bout
/// — ou un simple fichier. On tente d'abord la socket, puis on retombe sur
/// l'ajout en fin de fichier ; l'appelant n'a pas à choisir.
struct Sink {
    path: PathBuf,
    out: Option<Output>,
    /// Évite de répéter la même erreur d'ouverture à chaque rapport.
    complained: bool,
}

enum Output {
    Socket(UnixStream),
    File(File),
}

impl Write for Output {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Output::Socket(s) => s.write(buf),
            Output::File(f) => f.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Output::Socket(s) => s.flush(),
            Output::File(f) => f.flush(),
        }
    }
}

impl Sink {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            out: None,
            complained: false,
        }
    }

    /// Écrit une ligne, en rouvrant la sortie si elle a été perdue.
    ///
    /// Un collecteur qui redémarre ferme la socket : la première écriture
    /// échoue, la seconde repart sur une connexion neuve. Au-delà, l'erreur
    /// remonte et le rapport est perdu — la capture, elle, continue.
    fn write_line(&mut self, line: &str) -> io::Result<()> {
        for attempt in 0..2 {
            if self.out.is_none() {
                match open(&self.path) {
                    Ok(out) => {
                        self.out = Some(out);
                        self.complained = false;
                    }
                    Err(err) => {
                        let quiet = std::mem::replace(&mut self.complained, true);
                        return Err(if quiet { silent(err) } else { err });
                    }
                }
            }

            let out = self.out.as_mut().expect("sortie ouverte juste au-dessus");
            match out.write_all(line.as_bytes()).and_then(|()| {
                out.write_all(b"\n")?;
                out.flush()
            }) {
                Ok(()) => return Ok(()),
                // Sortie fermée sous nos pieds : on la rouvre une fois.
                Err(err) => {
                    self.out = None;
                    if attempt == 1 {
                        return Err(err);
                    }
                }
            }
        }
        unreachable!("la boucle rend un résultat à la seconde tentative")
    }
}

/// Ouvre la sortie : socket Unix si quelqu'un écoute, sinon fichier en ajout.
fn open(path: &Path) -> io::Result<Output> {
    match UnixStream::connect(path) {
        Ok(stream) => Ok(Output::Socket(stream)),
        Err(_) => OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map(Output::File),
    }
}

/// Même erreur, déjà signalée : l'appelant la taira.
fn silent(err: io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{err} (déjà signalé)"))
}

/// Construit la ligne de rapport.
///
/// `device` est l'état de l'interface, absent si `wg` n'a pas pu être lu :
/// le rapport part quand même, avec un pair nul, plutôt que d'être perdu.
pub fn payload(observation: &Observation, device: Option<&DeviceStatus>) -> String {
    let mut root = Object::new();
    root.string("domain", &observation.domain)
        .boolean("listed", true)
        .number("observed_at", observation.observed_at);

    let peer = device.and_then(|d| d.peer_for(observation.client));
    let mut client = Object::new();
    client.string("tunnel_ip", &observation.client.to_string());
    match peer {
        Some(peer) => {
            client
                .string("public_key", &peer.public_key)
                .maybe_string("endpoint", peer.endpoint.as_deref())
                .strings("allowed_ips", &peer.allowed_ips)
                .maybe_number("latest_handshake", peer.latest_handshake)
                .number("transfer_rx", peer.transfer_rx)
                .number("transfer_tx", peer.transfer_tx)
                .maybe_number("persistent_keepalive", peer.persistent_keepalive);
        }
        // Adresse qui n'appartient à aucun pair connu : le collecteur tranchera.
        None => {
            client.null("public_key").null("endpoint");
        }
    }
    root.object("client", client);

    let mut server = Object::new();
    match device {
        Some(device) => {
            server
                .string("device", &device.device)
                .string("public_key", &device.public_key)
                .number("listen_port", device.listen_port)
                .number("peers", device.peers.len());
        }
        None => {
            server.null("device").null("public_key");
        }
    }
    root.object("server", server);

    root.finish()
}

/// État des pairs, relu au plus une fois par `ttl`.
///
/// Chaque lecture lance `wg show … dump` : à raison d'un rapport par domaine
/// bloqué, l'appeler à chaque fois reviendrait à forker en boucle. La liste
/// des pairs ne change qu'au rythme des connexions, la garder au chaud
/// quelques secondes ne coûte aucune précision utile.
struct Peers {
    device: String,
    ttl: Duration,
    cached: Option<DeviceStatus>,
    fetched: Option<Instant>,
    /// Évite de répéter la même erreur à chaque rafraîchissement.
    complained: bool,
}

impl Peers {
    fn new(device: String, ttl: Duration) -> Self {
        Self {
            device,
            ttl,
            cached: None,
            fetched: None,
            complained: false,
        }
    }

    /// État courant, rafraîchi s'il a vieilli.
    fn current(&mut self) -> Option<&DeviceStatus> {
        if self.is_stale() {
            self.refresh();
        }
        self.cached.as_ref()
    }

    fn is_stale(&self) -> bool {
        match self.fetched {
            Some(at) => at.elapsed() >= self.ttl,
            None => true,
        }
    }

    fn refresh(&mut self) {
        self.fetched = Some(Instant::now());
        match wg::dump(&self.device) {
            Ok(status) => {
                self.cached = Some(status);
                self.complained = false;
            }
            // On garde le dernier état connu : une interface qui redémarre ne
            // doit pas priver les rapports de leur identité de pair.
            Err(err) => {
                if !self.complained {
                    eprintln!("rapport: pairs de {} illisibles — {err}", self.device);
                    self.complained = true;
                }
            }
        }
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::PeerStatus;

    fn device() -> DeviceStatus {
        DeviceStatus {
            device: "wg0".to_string(),
            public_key: "sPub=".to_string(),
            listen_port: 51820,
            peers: vec![PeerStatus {
                public_key: "peerA=".to_string(),
                endpoint: Some("203.0.113.7:51820".to_string()),
                allowed_ips: vec!["10.8.0.2/32".to_string()],
                latest_handshake: Some(1757030390),
                transfer_rx: 1024,
                transfer_tx: 2048,
                persistent_keepalive: Some(25),
            }],
        }
    }

    fn observation(client: &str) -> Observation {
        Observation {
            domain: "ads.example.com".to_string(),
            client: client.parse().unwrap(),
            observed_at: 1757030400,
        }
    }

    #[test]
    fn carries_the_public_key_and_the_endpoint_of_the_client() {
        let body = payload(&observation("10.8.0.2"), Some(&device()));
        for expected in [
            r#""domain":"ads.example.com""#,
            r#""listed":true"#,
            r#""observed_at":1757030400"#,
            r#""tunnel_ip":"10.8.0.2""#,
            r#""public_key":"peerA=""#,
            r#""endpoint":"203.0.113.7:51820""#,
            r#""allowed_ips":["10.8.0.2/32"]"#,
            r#""latest_handshake":1757030390"#,
            r#""transfer_rx":1024"#,
            r#""transfer_tx":2048"#,
            r#""persistent_keepalive":25"#,
            r#""listen_port":51820"#,
        ] {
            assert!(body.contains(expected), "{expected} absent de {body}");
        }
    }

    #[test]
    fn a_report_holds_on_a_single_line() {
        let body = payload(&observation("10.8.0.2"), Some(&device()));
        assert!(!body.contains('\n'), "rapport multiligne: {body}");
    }

    #[test]
    fn an_unknown_address_yields_a_null_peer_rather_than_no_report() {
        let body = payload(&observation("10.8.0.9"), Some(&device()));
        assert!(body.contains(r#""tunnel_ip":"10.8.0.9""#));
        assert!(body.contains(r#""public_key":null"#));
    }

    #[test]
    fn an_unreadable_interface_still_produces_a_report() {
        let body = payload(&observation("10.8.0.2"), None);
        assert!(body.contains(r#""device":null"#));
        assert!(body.contains(r#""tunnel_ip":"10.8.0.2""#));
    }

    #[test]
    fn a_disabled_reporter_swallows_observations() {
        let reporter = Reporter::disabled();
        assert!(!reporter.is_enabled());
        reporter.report(observation("10.8.0.2"));
    }

    #[test]
    fn writing_appends_one_line_per_report() {
        let path = std::env::temp_dir().join(format!("perses-sink-{}.socket", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let mut sink = Sink::new(path.clone());
        sink.write_line(r#"{"domain":"a.test"}"#).unwrap();
        sink.write_line(r#"{"domain":"b.test"}"#).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            written,
            "{\"domain\":\"a.test\"}\n{\"domain\":\"b.test\"}\n"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unreachable_path_is_an_error_not_a_panic() {
        let mut sink = Sink::new(PathBuf::from("/nonexistent-dir-perses/report.socket"));
        assert!(sink.write_line("{}").is_err());
    }

    #[test]
    fn peers_are_reread_only_once_their_ttl_has_passed() {
        let mut peers = Peers::new("nonexistent-device".to_string(), Duration::from_secs(60));
        assert!(peers.current().is_none());
        let first = peers.fetched;
        // Deuxième appel dans la fenêtre : aucune relecture.
        assert!(peers.current().is_none());
        assert_eq!(peers.fetched, first);
    }
}
