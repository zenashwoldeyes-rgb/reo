//! Persistence surface. The Run keys and Startup folders are where the vast
//! majority of commodity adware and "PUPs" hook themselves to survive reboot.
//! We enumerate them and flag entries that launch from transient locations.

use super::capture;
use super::types::{Finding, ScanReport};

const RUN_KEYS: &[&str] = &[
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
];

const SUSPECT_HINTS: &[&str] = &[
    r"\appdata\local\temp",
    r"\temp\",
    r"\tmp\",
    r"\downloads\",
    r"\users\public\",
    "powershell -enc",
    "-encodedcommand",
    "mshta",
    "rundll32",
];

pub fn scan(report: &mut ScanReport) {
    let mut total = 0usize;

    for key in RUN_KEYS {
        let Some(out) = capture("reg", &["query", key]) else {
            continue;
        };
        for line in out.lines() {
            let line = line.trim();
            // reg query rows look like:  Name    REG_SZ    "C:\path\to.exe"
            if !line.contains("REG_") {
                continue;
            }
            total += 1;
            let lower = line.to_lowercase();
            if let Some(hint) = SUSPECT_HINTS.iter().find(|h| lower.contains(**h)) {
                let name = line.split_whitespace().next().unwrap_or("<entry>");
                report.add(
                    Finding::new(
                        "persistence",
                        &format!("autorun entry `{name}`"),
                        &format!("launches via a suspicious pattern ({hint})"),
                        55,
                    )
                    .evidence(format!("{key}"))
                    .evidence(line.to_string())
                    .recommend("`remove` will delete this Run entry and the file it points at"),
                );
            }
        }
    }

    // Per-user Startup folder.
    if let Some(appdata) = dirs::config_dir() {
        let startup = appdata.join(r"Microsoft\Windows\Start Menu\Programs\Startup");
        if let Ok(entries) = std::fs::read_dir(&startup) {
            for e in entries.flatten() {
                total += 1;
                let name = e.file_name().to_string_lossy().to_string();
                if name.eq_ignore_ascii_case("desktop.ini") {
                    total -= 1;
                    continue;
                }
                report.add(
                    Finding::new(
                        "persistence",
                        &format!("startup item `{name}`"),
                        "auto-launches at login from the Startup folder",
                        20,
                    )
                    .evidence(e.path().to_string_lossy().into_owned())
                    .recommend("review; if you don't recognize it, `remove` it"),
                );
            }
        }
    }

    report.note_section("persistence", &format!("{total} autorun entries reviewed"));
}
