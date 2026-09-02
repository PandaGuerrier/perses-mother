//! Point d'entrée : dispatch des sous-commandes vers le module [`wg`].

use std::error::Error;
use std::process::ExitCode;

use perses_mother::cache::{Cache, CacheConfig};
use perses_mother::filter::{self, FilterConfig, Policy, BLACKLIST_SET};
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
    listen        Écoute l'interface et affiche les noms de domaine visités
                  (requêtes DNS en clair et SNI des poignées de main TLS)
    filter        Coupe les connexions vers les domaines de la liste noire
                  (Linux : nécessite une règle iptables NFQUEUE)
    blacklist     Gère la liste noire : add <domaine>… | rm <domaine>… | list

OPTIONS:
    -i, --interface <NOM>     Nom de l'interface           (défaut: wg0)
    -d, --config-dir <CHEMIN> Répertoire de conf           (défaut: /etc/wireguard)
    -a, --address <CIDR>      Adresse du serveur           (défaut: 10.8.0.1/24)
    -p, --port <PORT>         Port UDP d'écoute            (défaut: 51820)
    -w, --wan <IFACE>         Interface de sortie (ajoute les règles de NAT)
        --device <IFACE>      listen: capture cette interface plutôt que le tunnel
        --filter <BPF>        listen: filtre de capture
                              (défaut: udp port 53 or tcp port 443)
    -q, --queue <N>           filter: numéro de la file NFQUEUE (défaut: 0)
        --force               cold-start: régénère les clés existantes
    -h, --help                Affiche cette aide

EXEMPLES:
    sudo perses-mother listen | sort -u      # domaines uniques, au fil de l'eau
    sudo perses-mother listen --device en0   # écouter une autre interface
    perses-mother blacklist add pub.example  # interdire un domaine
    sudo perses-mother filter                # appliquer la liste noire

La liste noire est lue dans Redis : définir REDIS_PASSWORD dans
l'environnement du processus (sudo -E, ou sudo VAR=... perses-mother …).
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

    let mut cache = Cache::connect(CacheConfig::from_env()?)?;

    if !cache.exists("chatgpt.com")? {
        cache.set("chatgpt.com", "true").ok();
    }

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
            sniff::sniff(&sniff_cfg, cache)?;
        }
        "blacklist" => {
            let mut cache = Cache::connect(CacheConfig::from_env()?)?;
            let (action, domains) = match opts.positional.split_first() {
                Some((action, rest)) => (action.as_str(), rest),
                None => ("list", &[][..]),
            };
            match action {
                "add" => {
                    require_domains(domains)?;
                    for domain in domains {
                        let added = cache.add_to_set(BLACKLIST_SET, domain)?;
                        println!("{domain} {}", if added { "ajouté" } else { "déjà listé" });
                    }
                }
                "rm" | "remove" => {
                    require_domains(domains)?;
                    for domain in domains {
                        let removed = cache.remove_from_set(BLACKLIST_SET, domain)?;
                        println!("{domain} {}", if removed { "retiré" } else { "absent" });
                    }
                }
                "list" => {
                    let mut domains = cache.set_members(BLACKLIST_SET)?;
                    domains.sort();
                    for domain in &domains {
                        println!("{domain}");
                    }
                    eprintln!("{} domaine(s) dans la liste noire", domains.len());
                }
                other => {
                    return Err(format!("action inconnue: {other} (add | rm | list)").into());
                }
            }
        }
        "filter" => {
            let mut filter_cfg = FilterConfig::default();
            if let Some(queue) = opts.queue {
                filter_cfg.queue = queue;
            }
            let policy = Policy::new(Cache::connect(CacheConfig::from_env()?)?);
            // Le filtre ne pose pas la règle lui-même : toucher au pare-feu
            // d'un serveur en production est la décision de son administrateur.
            eprintln!(
                "règle à poser si ce n'est pas déjà fait :\n  {}",
                filter::iptables_rule(filter_cfg.queue, &cfg.interface)
            );
            // `filter` boucle indéfiniment : on n'en sort que par Ctrl-C, ou
            // sur une erreur fatale qui remonte ici.
            filter::filter(&filter_cfg, policy)?;
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
    queue: Option<u16>,
    /// Arguments qui ne sont pas des options, dans l'ordre.
    positional: Vec<String>,
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
            "-q" | "--queue" => opts.queue = Some(value()?.parse()?),
            "--force" => opts.force = true,
            other if other.starts_with('-') => {
                return Err(format!("option inconnue: {other}").into())
            }
            other => opts.positional.push(other.to_string()),
        }
    }
    Ok(opts)
}

fn require_domains(domains: &[String]) -> Result<(), Box<dyn Error>> {
    if domains.is_empty() {
        return Err("préciser au moins un domaine".into());
    }
    Ok(())
}
