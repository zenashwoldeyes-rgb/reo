//! Process surface. We look for the cheap, high-signal tells that adware and
//! commodity malware leave behind: executing from a temp/cache directory,
//! masquerading filenames, and runaway resource use.

use super::types::{Finding, ScanReport};
use sysinfo::System;

/// Directories an executable has no business living in for a legitimate,
/// installed program. Matched case-insensitively against the exe path.
const SUSPECT_DIRS: &[&str] = &[
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\temp\",
    r"\tmp\",
    r"\downloads\",
    r"\users\public\",
];

/// Document/media extensions that, when they precede an executable extension,
/// indicate a masquerade (e.g. `invoice.pdf.exe`). A normal dotted program name
/// like `NVDisplay.Container.exe` is NOT a masquerade.
const DOC_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "csv",
    "rtf", "zip", "rar", "7z", "mp3", "mp4", "avi", "mov", "html", "htm", "lnk",
];

const EXEC_EXTS: &[&str] = &["exe", "scr", "com", "bat", "cmd", "pif"];

/// True only when the filename is `<...>.<docext>.<execext>` — the classic
/// double-extension trick. Avoids flagging legitimate dotted binary names.
fn is_double_extension(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 3 {
        return false;
    }
    let last = parts[parts.len() - 1];
    let penultimate = parts[parts.len() - 2];
    EXEC_EXTS.contains(&last) && DOC_EXTS.contains(&penultimate)
}

pub fn scan(sys: &System, report: &mut ScanReport) {
    let processes = sys.processes();
    let mut suspect = 0usize;

    for process in processes.values() {
        let name = process.name().to_string_lossy().to_string();
        let exe = process
            .exe()
            .map(|p| p.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let pid = process.pid().as_u32();

        let mut score: u8 = 0;
        let mut reasons: Vec<String> = Vec::new();

        // Strong signal: a binary executing from a transient/cache directory.
        // (An empty exe path is an access artifact on Windows for processes we
        // can't open without elevation — it is NOT treated as suspicious.)
        if !exe.is_empty() {
            if let Some(dir) = SUSPECT_DIRS.iter().find(|d| exe.contains(**d)) {
                score = score.saturating_add(45);
                reasons.push(format!("runs from a transient location ({})", dir.trim_matches('\\')));
            }
        }

        // Double-extension masquerade, e.g. invoice.pdf.exe — but not ordinary
        // dotted program names like NVDisplay.Container.exe.
        let lname = name.to_lowercase();
        if is_double_extension(&lname) {
            score = score.saturating_add(40);
            reasons.push("double-extension filename (masquerade pattern)".to_string());
        }

        if score == 0 {
            continue;
        }

        suspect += 1;
        let cmd: Vec<String> = process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();

        let mut finding = Finding::new(
            "process",
            &format!("{name} (pid {pid})"),
            &reasons.join("; "),
            score.min(100),
        )
        .evidence(format!(
            "image: {}",
            if exe.is_empty() { "<unknown>".into() } else { exe.clone() }
        ))
        .recommend("run `remove` and REO will terminate it, then quarantine the image and clear any persistence");

        if !cmd.is_empty() {
            finding = finding.evidence(format!("cmdline: {}", cmd.join(" ")));
        }
        report.add(finding);
    }

    report.note_section(
        "processes",
        &format!("{} scanned, {} flagged", processes.len(), suspect),
    );
}

#[cfg(test)]
mod tests {
    use super::is_double_extension;

    #[test]
    fn flags_real_masquerades() {
        assert!(is_double_extension("invoice.pdf.exe"));
        assert!(is_double_extension("photo.jpg.scr"));
        assert!(is_double_extension("report.docx.cmd"));
    }

    #[test]
    fn ignores_legitimate_dotted_names() {
        assert!(!is_double_extension("nvdisplay.container.exe"));
        assert!(!is_double_extension("dell.d3.winsvc.exe"));
        assert!(!is_double_extension("chrome.exe"));
        assert!(!is_double_extension("svchost.exe"));
    }
}
