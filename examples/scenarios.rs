//! Écrit les captures de test (scénarios) dans un dossier, pour les rejouer
//! avec le sniffer :
//!
//! ```text
//! cargo run --example scenarios -- scenarios/          # date fixe : 1er janvier 2026
//! cargo run --example scenarios -- scenarios/ --now    # date et heure actuelles
//! cargo run -- --read scenarios/desordre.pcap
//! ```
//!
//! Les scénarios sont définis dans `tests/common/mod.rs`, partagés avec les
//! tests d'intégration.

#[path = "../tests/common/mod.rs"]
mod common;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // `--now` : horodater les captures à l'instant présent plutôt qu'à la date
    // fixe, par exemple pour des captures d'écran datées du jour.
    let now = args.iter().any(|arg| arg == "--now");
    let dir = args
        .iter()
        .find(|arg| !arg.starts_with("--"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("scenarios"));

    let start = if now {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("horloge système antérieure à 1970")
    } else {
        common::DEFAULT_START
    };

    std::fs::create_dir_all(&dir)?;
    for scenario in common::scenarios_at(start) {
        let path = dir.join(format!("{}.pcap", scenario.name));
        common::write_pcap(&path, &scenario.frames)?;
        println!("{:<45} {}", path.display(), scenario.description);
    }
    Ok(())
}