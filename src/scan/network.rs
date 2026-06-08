//! Network surface. We enumerate active sockets from the OS (no packets are
//! sent) and classify each: loopback, LAN, a listener, or an outbound
//! connection to public infrastructure — the last being what "phoning home"
//! looks like.

use super::types::{Finding, ScanReport};
use super::{capture, is_private_ip};
use sysinfo::{Pid, System};

#[derive(Debug, Clone)]
pub struct Connection {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub pid: u32,
    pub process: String,
    pub class: Class,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Loopback,
    Lan,
    Listen,
    Public,
}

impl Class {
    pub fn label(self) -> &'static str {
        match self {
            Class::Loopback => "loopback",
            Class::Lan => "lan",
            Class::Listen => "listening",
            Class::Public => "public",
        }
    }
}

/// Enumerate connections and resolve owning process names.
pub fn collect(sys: &System) -> Vec<Connection> {
    let raw = match capture("netstat", &["-ano"]) {
        Some(out) => out,
        None => return Vec::new(),
    };

    let mut conns = Vec::new();
    for line in raw.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Expected: PROTO  LOCAL  FOREIGN  [STATE]  PID
        if f.len() < 4 {
            continue;
        }
        let proto = f[0].to_uppercase();
        if proto != "TCP" && proto != "UDP" {
            continue;
        }
        let (local, remote, state, pid_str) = if proto == "TCP" && f.len() >= 5 {
            (f[1], f[2], f[3], f[4])
        } else {
            // UDP rows have no state column.
            (f[1], f[2], "-", f[f.len() - 1])
        };
        let pid: u32 = pid_str.parse().unwrap_or(0);
        let process = sys
            .process(Pid::from_u32(pid))
            .map(|p| p.name().to_string_lossy().into_owned())
            .unwrap_or_else(|| "?".to_string());

        let remote_ip = remote.rsplit_once(':').map(|(h, _)| h).unwrap_or(remote);
        let class = if state.eq_ignore_ascii_case("LISTENING") {
            Class::Listen
        } else if remote_ip.starts_with("127.") || remote_ip == "::1" || remote_ip == "0.0.0.0" {
            Class::Loopback
        } else if is_private_ip(remote_ip) {
            Class::Lan
        } else {
            Class::Public
        };

        conns.push(Connection {
            proto,
            local: local.to_string(),
            remote: remote.to_string(),
            state: state.to_string(),
            pid,
            process,
            class,
        });
    }
    conns
}

/// Heuristic risk for a single public connection. Without a threat-intel feed
/// (an explicit opt-in sync), we score on shape: which process, which port.
fn score_public(conn: &Connection) -> (u8, String) {
    let port = conn
        .remote
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(0);

    // Browsers and well-known updaters talk to the internet constantly; that is
    // expected and low-signal. An unknown process on an odd port is not.
    let benign_proc = matches!(
        conn.process.to_lowercase().as_str(),
        "chrome.exe"
            | "msedge.exe"
            | "firefox.exe"
            | "brave.exe"
            | "svchost.exe"
            | "spotify.exe"
            | "slack.exe"
            | "code.exe"
    );
    // 53 = DNS, 123 = NTP — ordinary background traffic.
    let common_port = matches!(port, 53 | 80 | 123 | 443 | 853 | 8080 | 8443);

    match (benign_proc, common_port) {
        (true, _) => (8, "known application over an expected port".into()),
        // Unknown process on a standard web/DNS port is the common case for
        // ordinary apps — informational only, kept below the finding threshold.
        (false, true) => (
            12,
            format!("{} is talking to the internet on :{port}", conn.process),
        ),
        (false, false) => (
            48,
            format!(
                "{} has an outbound session on uncommon port :{port}",
                conn.process
            ),
        ),
    }
}

pub fn scan(sys: &System, report: &mut ScanReport) {
    let conns = collect(sys);
    let public = conns.iter().filter(|c| c.class == Class::Public).count();
    let listening = conns.iter().filter(|c| c.class == Class::Listen).count();

    // A "phoning home" finding requires an *active* outbound session. TIME_WAIT
    // / CLOSE_WAIT are residue, and pid 0 (System Idle) owns no real socket.
    let active_public = conns.iter().filter(|c| {
        c.class == Class::Public
            && c.state.eq_ignore_ascii_case("ESTABLISHED")
            && c.pid != 0
            && !matches!(c.process.as_str(), "Idle" | "System")
    });
    for conn in active_public {
        let (score, why) = score_public(conn);
        if score < 20 {
            continue;
        }
        report.add(
            Finding::new(
                "network",
                &format!("{} → {}", conn.process, conn.remote),
                &why,
                score,
            )
            .evidence(format!(
                "{} local {} state {} pid {}",
                conn.proto, conn.local, conn.state, conn.pid
            ))
            .recommend("ask `what's running on my network` for the full map, or `lock down` to cut untrusted egress"),
        );
    }

    report.note_section(
        "network",
        &format!(
            "{} connections ({} public, {} listening)",
            conns.len(),
            public,
            listening
        ),
    );
}
