//! Collecte des flux sortants de l'hôte (Phase C — surveillance « out »).
//!
//! Lit `/proc/net/tcp` et `/proc/net/tcp6` (Linux), garde les connexions
//! ÉTABLIES vers une IP **publique**, et renvoie la liste des destinations.
//! L'API les confronte aux blocklists embarquées + heuristiques de scan.
//! Vide hors Linux (les fichiers /proc n'existent pas).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Flow {
    pub remote_ip: String,
    pub remote_port: u16,
    pub local_port: u16,
}

/// Connexions sortantes établies vers des IP publiques (dédupliquées).
pub fn collect_flows() -> Vec<Flow> {
    let mut seen: HashSet<(String, u16)> = HashSet::new();
    let mut out = Vec::new();
    parse_proc_net("/proc/net/tcp", false, &mut seen, &mut out);
    parse_proc_net("/proc/net/tcp6", true, &mut seen, &mut out);
    out
}

fn parse_proc_net(
    path: &str,
    is_v6: bool,
    seen: &mut HashSet<(String, u16)>,
    out: &mut Vec<Flow>,
) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    // En-tête : sl local_address rem_address st ...
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 || cols[3] != "01" {
            continue; // 01 = ESTABLISHED
        }
        let Some((rip, rport)) = parse_addr(cols[2], is_v6) else {
            continue;
        };
        if !is_public(&rip) {
            continue;
        }
        let lport = parse_addr(cols[1], is_v6).map(|(_, p)| p).unwrap_or(0);
        let ip_str = rip.to_string();
        if seen.insert((ip_str.clone(), rport)) {
            out.push(Flow {
                remote_ip: ip_str,
                remote_port: rport,
                local_port: lport,
            });
        }
    }
}

/// Parse "HEXIP:HEXPORT" (format /proc, little-endian par mot de 32 bits).
fn parse_addr(s: &str, is_v6: bool) -> Option<(IpAddr, u16)> {
    let (hip, hport) = s.split_once(':')?;
    let port = u16::from_str_radix(hport, 16).ok()?;
    if is_v6 {
        if hip.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for w in 0..4 {
            let word = u32::from_str_radix(&hip[w * 8..w * 8 + 8], 16).ok()?;
            bytes[w * 4..w * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Some((IpAddr::V6(Ipv6Addr::from(bytes)), port))
    } else {
        let raw = u32::from_str_radix(hip, 16).ok()?;
        Some((IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())), port))
    }
}

/// IP routable « publique » (exclut privé/loopback/link-local/multicast…).
fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast())
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            let is_link_local = (seg0 & 0xffc0) == 0xfe80;
            let is_unique_local = (seg0 & 0xfe00) == 0xfc00;
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_link_local
                || is_unique_local)
        }
    }
}
