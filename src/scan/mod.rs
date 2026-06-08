//! System scanning. Each submodule owns one surface (processes, network,
//! persistence, scheduled tasks) and returns explainable findings. Nothing here
//! touches the network — every signal is read from the local machine via
//! OS-native facilities.
//!
//! NOTE: production REO reads these signals through ETW (Windows), eBPF (Linux),
//! and the Endpoint Security Framework (macOS). This build uses the equivalent
//! user-space sources (sysinfo + native query tools) so the agent is fully
//! functional today without a kernel driver. The finding/scoring layer above is
//! identical regardless of source.

pub mod network;
mod processes;
mod startup;
mod tasks;
pub mod types;

use crate::config::Context;
use crate::ui;
use std::process::Command;
use sysinfo::System;
use types::ScanReport;

pub struct ScanOptions {
    pub quick: bool,
}

/// Run every scan section and aggregate the results into one report.
pub fn full_scan(_ctx: &Context, opts: ScanOptions) -> ScanReport {
    let mut report = ScanReport::default();

    let mut sys = System::new_all();
    // A second refresh after a short pause lets CPU usage settle to real values.
    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_all();

    step("Processes");
    processes::scan(&sys, &mut report);

    step("Network connections");
    network::scan(&sys, &mut report);

    step("Startup & persistence");
    startup::scan(&mut report);

    if opts.quick {
        ui::dim("   (quick mode: skipped scheduled-task sweep)");
    } else {
        step("Scheduled tasks");
        tasks::scan(&mut report);
    }

    report
}

fn step(name: &str) {
    ui::info(&format!("scanning {name}…"));
}

/// Run an OS command and capture stdout as a String. Returns None on failure so
/// callers degrade gracefully when a tool is missing or access is denied.
pub(crate) fn capture(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    if out.stdout.is_empty() && !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// True for addresses we never treat as "phoning home": loopback, link-local,
/// and RFC1918 private ranges.
pub(crate) fn is_private_ip(ip: &str) -> bool {
    let ip = ip.trim();
    if ip == "0.0.0.0" || ip == "*" || ip == "::" || ip.starts_with("::1") {
        return true;
    }
    if ip.starts_with("127.") || ip.starts_with("169.254.") || ip.starts_with("fe80") {
        return true;
    }
    if ip.starts_with("10.") || ip.starts_with("192.168.") {
        return true;
    }
    // 172.16.0.0 – 172.31.255.255
    if let Some(rest) = ip.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next() {
            if let Ok(n) = second.parse::<u8>() {
                if (16..=31).contains(&n) {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::is_private_ip;

    #[test]
    fn private_and_loopback_are_local() {
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.4.4", "172.31.255.1", "::1", "fe80::1", "0.0.0.0"] {
            assert!(is_private_ip(ip), "{ip} should be local");
        }
    }

    #[test]
    fn public_ips_are_not_local() {
        for ip in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "64.59.176.13", "172.15.0.1"] {
            assert!(!is_private_ip(ip), "{ip} should be public");
        }
    }
}
