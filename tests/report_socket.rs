//! Le rapporteur, vu depuis l'autre bout de la socket.
//!
//! Un collecteur minimal écoute sur une socket Unix éphémère : on regarde ce
//! qui y arrive vraiment — une ligne, du JSON, un rapport — plutôt que ce que
//! le code prétend écrire. Le second test couvre l'autre bout possible du
//! chemin : un fichier ordinaire, sans personne à l'écoute.

use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use perses_mother::report::{Observation, ReportConfig, Reporter};

/// Au-delà, le test échoue au lieu de s'éterniser.
const PATIENCE: Duration = Duration::from_secs(10);

/// Chemin propre à ce test, effacé s'il traînait d'une exécution précédente.
fn path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("perses-{name}-{}.socket", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn config(socket: PathBuf) -> ReportConfig {
    ReportConfig {
        socket,
        queue: 8,
        // Le périphérique sera bidon : `wg show` échouera, et c'est le cas
        // qu'on veut couvrir — le rapport doit partir quand même.
        peers_ttl: Duration::from_secs(60),
    }
}

#[test]
fn writes_one_json_line_per_report_to_the_socket() {
    let socket = path("collector");
    let listener = UnixListener::bind(&socket).expect("socket d'écoute");

    let reporter = Reporter::spawn(config(socket.clone()), "perses-test-wg");
    reporter.report(Observation::now(
        "ads.example.com",
        "10.8.0.2".parse().unwrap(),
    ));

    let (stream, _) = listener.accept().expect("connexion attendue");
    stream.set_read_timeout(Some(PATIENCE)).unwrap();
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .expect("lecture du rapport");

    assert!(line.ends_with('\n'), "ligne non terminée: {line:?}");
    assert!(line.contains(r#""domain":"ads.example.com""#));
    assert!(line.contains(r#""listed":true"#));
    assert!(line.contains(r#""tunnel_ip":"10.8.0.2""#));
    // L'interface n'existe pas : le pair est inconnu, mais le rapport part.
    assert!(line.contains(r#""public_key":null"#));

    let _ = std::fs::remove_file(&socket);
}

#[test]
fn falls_back_on_a_plain_file_when_nobody_listens() {
    let socket = path("plain-file");

    let reporter = Reporter::spawn(config(socket.clone()), "perses-test-wg");
    reporter.report(Observation::now(
        "tracker.example.com",
        "10.8.0.3".parse().unwrap(),
    ));
    reporter.report(Observation::now(
        "ads.example.com",
        "10.8.0.4".parse().unwrap(),
    ));

    // L'écriture est asynchrone : on attend les deux lignes, pas plus.
    let deadline = Instant::now() + PATIENCE;
    let content = loop {
        let content = std::fs::read_to_string(&socket).unwrap_or_default();
        if content.lines().count() == 2 {
            break content;
        }
        assert!(Instant::now() < deadline, "rapports absents de {socket:?}");
        std::thread::sleep(Duration::from_millis(20));
    };

    let mut lines = content.lines();
    assert!(lines
        .next()
        .unwrap()
        .contains(r#""domain":"tracker.example.com""#));
    assert!(lines
        .next()
        .unwrap()
        .contains(r#""domain":"ads.example.com""#));

    let _ = std::fs::remove_file(&socket);
}

#[test]
fn a_disabled_reporter_writes_nothing() {
    let socket = path("disabled");

    let reporter = Reporter::disabled();
    assert!(!reporter.is_enabled());
    reporter.report(Observation::now(
        "x.example.com",
        "10.8.0.5".parse().unwrap(),
    ));

    assert!(!socket.exists());
}
