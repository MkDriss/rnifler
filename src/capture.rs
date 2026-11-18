//! Module `capture` : tout ce qui dépend de libpcap est isolé ici.
//!
//! Objectif d'architecture : le reste du programme (parsing, réassemblage,
//! décodage MQTT) ne manipule que des tranches d'octets `&[u8]`. Il ne sait
//! pas d'où viennent les paquets : interface réseau ([`open_live`],
//! [`open_live_with`]) ou fichier de capture `.pcap` ([`open_offline`]).

use std::path::Path;
use std::time::Duration;

use pcap::{Active, Capture, Device, Offline, PacketHeader};

/// Réglages d'une capture live.
///
/// `#[non_exhaustive]` : le code extérieur à rnifler ne peut pas construire
/// cette struct champ par champ. Il part de `LiveOptions::default()` et
/// modifie ce qu'il veut. Ajouter une option plus tard ne cassera donc aucun
/// programme existant (version mineure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LiveOptions {
    /// Octets conservés au maximum pour chaque paquet.
    pub snaplen: i32,
    /// `next_packet()` rend la main après ce délai sans paquet (millisecondes).
    pub timeout_ms: i32,
    /// Mode promiscuité : recevoir aussi les trames adressées à d'AUTRES
    /// machines. Sans lui, sur un point d'accès WiFi, les trames échangées
    /// directement entre deux stations ne sont pas vues (vérifié sur un
    /// Raspberry Pi 4 en mode AP, avec hostapd et `ap_isolate=0`).
    pub promiscuous: bool,
}

impl Default for LiveOptions {
    /// Les réglages historiques de `open_live` : 65535 octets, 1 s, et pas
    /// de mode promiscuité.
    fn default() -> Self {
        LiveOptions {
            snaplen: 65535,
            timeout_ms: 1000,
            promiscuous: false,
        }
    }
}

/// Ouvre une capture live sur `interface` et applique le filtre BPF `bpf_filter`.
///
/// Équivalent à [`open_live_with`] sans mode promiscuité. Conservée telle
/// quelle pour les programmes qui l'utilisent déjà.
pub fn open_live(
    interface: &str,
    bpf_filter: &str,
    snaplen: i32,
    timeout_ms: i32,
) -> Result<Capture<Active>, pcap::Error> {
    open_live_with(
        interface,
        bpf_filter,
        LiveOptions {
            snaplen,
            timeout_ms,
            promiscuous: false,
        },
    )
}

/// Ouvre une capture live sur `interface` avec les réglages `options`, et
/// applique le filtre BPF `bpf_filter`.
///
/// Typestate de la crate pcap :
///   `Capture::from_device()` -> `Capture<Inactive>` (on configure)
///   `.open()`                -> `Capture<Active>`   (on lit des paquets)
/// `open(self)` prend `self` PAR VALEUR : la poignée inactive est « consommée »
/// (move), le compilateur interdit donc de la réutiliser après activation.
pub fn open_live_with(
    interface: &str,
    bpf_filter: &str,
    options: LiveOptions,
) -> Result<Capture<Active>, pcap::Error> {
    let mut cap = Capture::from_device(interface)? // Capture<Inactive>
        .snaplen(options.snaplen) // octets max conservés par paquet
        .timeout(options.timeout_ms) // next_packet() rend la main après ce délai
        .promisc(options.promiscuous) // trames destinées à d'autres machines
        .immediate_mode(true) // livre chaque paquet dès son arrivée
        .open()?; // Capture<Active> (c'est ici qu'il faut les privilèges)

    // Le filtre BPF est compilé par libpcap et exécuté dans le noyau :
    // les paquets non désirés ne remontent jamais jusqu'à notre programme.
    cap.filter(bpf_filter, true)?;

    Ok(cap)
}

/// Ouvre un fichier de capture (format pcap, par exemple produit par
/// `tcpdump -w`) et applique le filtre BPF `bpf_filter`.
///
/// Aucun privilège n'est nécessaire : on lit un fichier, pas une interface.
/// Pour un fichier, le filtre est appliqué par libpcap dans le programme,
/// et non dans le noyau.
pub fn open_offline(path: &Path, bpf_filter: &str) -> Result<Capture<Offline>, pcap::Error> {
    let mut cap = Capture::from_file(path)?;
    cap.filter(bpf_filter, true)?;
    Ok(cap)
}

/// Horodatage de capture d'une trame, converti en `Duration` (temps écoulé
/// depuis le 1er janvier 1970).
pub fn timestamp(header: &PacketHeader) -> Duration {
    // Les champs de `timeval` sont signés ; une valeur négative est impossible
    // en pratique, et serait remplacée par 0 plutôt que de faire paniquer.
    let secs = u64::try_from(header.ts.tv_sec).unwrap_or(0);
    let micros = u32::try_from(header.ts.tv_usec).unwrap_or(0).min(999_999);
    Duration::new(secs, micros * 1000)
}

/// Liste les interfaces visibles par libpcap (équivalent de `tcpdump -D`).
pub fn list_interfaces() -> Result<Vec<Device>, pcap::Error> {
    Device::list()
}

/// L'interface nommée `name`, avec ses adresses et ses propriétés
/// (par exemple `flags.is_loopback()`), si elle existe.
pub fn find_interface(name: &str) -> Result<Option<Device>, pcap::Error> {
    Ok(Device::list()?.into_iter().find(|dev| dev.name == name))
}

// ===========================================================================
// Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_reglages_par_defaut_sont_ceux_de_open_live() {
        // `open_live` doit garder son comportement historique.
        let options = LiveOptions::default();
        assert_eq!(options.snaplen, 65535);
        assert_eq!(options.timeout_ms, 1000);
        assert!(!options.promiscuous);
    }

    #[test]
    fn une_interface_inexistante_est_une_erreur() {
        // Aucun privilège nécessaire : l'ouverture échoue avant toute capture.
        // (Dans rnifler, la syntaxe `..Default::default()` reste permise ; hors
        // de rnifler, `#[non_exhaustive]` l'interdit : voir `main.rs`.)
        let options = LiveOptions {
            promiscuous: true,
            ..LiveOptions::default()
        };
        assert!(open_live_with("rnifler-test-inexistante", "", options).is_err());
    }
}
