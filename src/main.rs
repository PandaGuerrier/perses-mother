//! Point d'entrée : dispatch des sous-commandes vers le module [`wg`].

use std::error::Error;
use std::process::ExitCode;

use perses_mother::sniff::{self, SniffConfig};
use perses_mother::wg::{self, ServerConfig, StartOutcome, StopOutcome};

const USAGE: &str = "\
perses-mother — gestion d'un serveur WireGuard

USAGE:
    perses-mother <COMMANDE> [OPTIONS]

COMMANDES:
    cold-start    Génère la paire de clés du serveur et le fichier de conf
    start         Monte l'interface (wg-quick up) — nécessite root
    stop          Descend l'interface (wg-quick down) — nécessite root
    status        Affiche l'état de l'interface
    listen        Écoute l'interface et affiche les noms de domaine résolus

OPTIONS:
    -i, --interface <NOM>     Nom de l'interface           (défaut: wg0)
    -d, --config-dir <CHEMIN> Répertoire de conf           (défaut: /etc/wireguard)
    -a, --address <CIDR>      Adresse du serveur           (défaut: 10.8.0.1/24)
    -p, --port <PORT>         Port UDP d'écoute            (défaut: 51820)
    -w, --wan <IFACE>         Interface de sortie (ajoute les règles de NAT)
        --device <IFACE>      listen: capture cette interface plutôt que le tunnel
        --filter <BPF>        listen: filtre de capture (défaut: udp port 53)
        --force               cold-start: régénère les clés existantes
    -h, --help                Affiche cette aide

EXEMPLES:
    sudo perses-mother listen | sort -u      # domaines uniques, au fil de l'eau
    sudo perses-mother listen --device en0   # écouter une autre interface
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("erreur: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let Some(command) = args.first() else {
        print!("{USAGE}");
        return Ok(());
    };
    if matches!(command.as_str(), "-h" | "--help" | "help") {
        print!("{USAGE}");
        return Ok(());
    }

    let opts = parse_options(&args[1..])?;
    let cfg = &opts.server;

    match command.as_str() {
        "cold-start" => {
            let out = wg::cold_start(cfg, opts.force)?;
            if out.created {
                println!("configuration écrite: {}", out.config_path.display());
            } else {
                println!(
                    "configuration déjà présente: {} (--force pour régénérer)",
                    out.config_path.display()
                );
            }
            println!("clé publique du serveur: {}", out.public_key);
        }
        "start" => match wg::start(cfg)? {
            StartOutcome::Started { device } => {
                println!("interface {} montée ({device})", cfg.interface)
            }
            StartOutcome::AlreadyRunning { device } => {
                println!("interface {} déjà active ({device})", cfg.interface)
            }
        },
        "stop" => match wg::stop(cfg)? {
            StopOutcome::Stopped => println!("interface {} arrêtée", cfg.interface),
            StopOutcome::AlreadyStopped => println!("interface {} déjà arrêtée", cfg.interface),
        },
        "status" => match wg::status(cfg)? {
            Some(status) => {
                println!("interface {} active ({})", cfg.interface, status.device);
                print!("{}", status.details);
            }
            None => println!("interface {} arrêtée", cfg.interface),
        },
        "listen" => {
            let device = match &opts.device {
                Some(device) => device.clone(),
                // Sous macOS, l'interface logique `wg0` est un `utunN` : c'est
                // ce nom-là que la capture attend.
                None => wg::resolve_device(&cfg.interface)?.ok_or_else(|| {
                    format!(
                        "interface {} arrêtée — lancer `start` d'abord",
                        cfg.interface
                    )
                })?,
            };
            let mut sniff_cfg = SniffConfig::new(device);
            if let Some(filter) = &opts.filter {
                sniff_cfg.filter = filter.clone();
            }
            // `sniff` boucle indéfiniment : on n'en sort que par Ctrl-C, ou
            // sur une erreur fatale qui remonte ici.
            sniff::sniff(&sniff_cfg)?;
        }
        other => {
            return Err(format!("commande inconnue: {other}\n\n{USAGE}").into());
        }
    }
    Ok(())
}

/// Options de ligne de commande, toutes commandes confondues.
#[derive(Debug, Default)]
struct Options {
    server: ServerConfig,
    force: bool,
    device: Option<String>,
    filter: Option<String>,
}

fn parse_options(args: &[String]) -> Result<Options, Box<dyn Error>> {
    let mut opts = Options::default();
    let cfg = &mut opts.server;
    let mut it = args.iter();

    while let Some(arg) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("l'option {arg} attend une valeur"))
        };
        match arg.as_str() {
            "-i" | "--interface" => cfg.interface = value()?,
            "-d" | "--config-dir" => cfg.config_dir = value()?.into(),
            "-a" | "--address" => cfg.address = value()?,
            "-p" | "--port" => cfg.listen_port = value()?.parse()?,
            "-w" | "--wan" => cfg.wan_interface = Some(value()?),
            "--device" => opts.device = Some(value()?),
            "--filter" => opts.filter = Some(value()?),
            "--force" => opts.force = true,
            other => return Err(format!("option inconnue: {other}").into()),
        }
    }
    Ok(opts)
}
