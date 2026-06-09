//! Scheduled-task surface. Tasks are a favorite persistence and "living off the
//! land" mechanism. We enumerate them via schtasks and flag actions that run
//! interpreters with encoded payloads, launch from transient directories, or
//! hide their window from outside a trusted location.
//!
//! Calibration matters here: a bare `-WindowStyle Hidden` is *not* by itself a
//! reliable signal — Windows' own built-in tasks (e.g. the SMBv1 cleanup tasks)
//! and plenty of legitimate installed software use it. So hidden-window only
//! counts when the binary runs from outside a trusted, signed location; the
//! high-confidence indicators (encoded commands, temp-dir execution, download
//! LOLBins) flag wherever they appear.

use super::capture;
use super::types::{Finding, ScanReport};

/// High-confidence abuse indicators. These flag HIGH no matter where they run.
const STRONG_HINTS: &[&str] = &[
    r"\appdata\local\temp",
    r"\temp\",
    r"\downloads\",
    "powershell -enc",
    "-encodedcommand",
    "mshta",
    "bitsadmin",
    "certutil -urlcache",
];

/// Hidden-window launches — a real technique, but low-signal on its own, so it
/// only counts from an untrusted location (see `is_trusted_location`).
const HIDDEN_WINDOW_HINTS: &[&str] = &["-windowstyle hidden", "-w hidden"];

pub fn scan(report: &mut ScanReport) {
    // CSV verbose output: one row per task with a "Task To Run" column.
    let Some(out) = capture("schtasks", &["/query", "/fo", "CSV", "/v"]) else {
        report.note_section("scheduled tasks", "schtasks unavailable");
        return;
    };

    let mut lines = out.lines();
    let header = match lines.next() {
        Some(h) => h,
        None => return,
    };
    let cols: Vec<&str> = parse_csv_row(header);
    let name_idx = cols.iter().position(|c| *c == "TaskName");
    let run_idx = cols.iter().position(|c| *c == "Task To Run");

    let mut total = 0usize;
    for line in lines {
        let row = parse_csv_row(line);
        if row.len() != cols.len() {
            continue;
        }
        total += 1;
        let run = run_idx.and_then(|i| row.get(i)).copied().unwrap_or("");
        let name = name_idx.and_then(|i| row.get(i)).copied().unwrap_or("<task>");
        if let Some(finding) = classify_task(name, run) {
            report.add(finding);
        }
    }

    report.note_section("scheduled tasks", &format!("{total} tasks enumerated"));
}

/// Decide whether a task's action is suspicious. Returns a scored `Finding`, or
/// `None` when the action is benign. Pure and unit-tested.
fn classify_task(name: &str, run: &str) -> Option<Finding> {
    let lower = run.to_lowercase();

    if let Some(hint) = STRONG_HINTS.iter().find(|h| lower.contains(**h)) {
        return Some(task_finding(name, run, hint, 60));
    }

    if let Some(hint) = HIDDEN_WINDOW_HINTS.iter().find(|h| lower.contains(**h)) {
        if !is_trusted_location(&lower) {
            // Hidden window from an untrusted path: suspicious, medium confidence.
            return Some(task_finding(name, run, hint, 45));
        }
    }

    None
}

/// Locations trusted enough that a hidden window alone isn't suspicious: the
/// Windows directory (OS components) and installed-program directories.
fn is_trusted_location(run_lower: &str) -> bool {
    const TRUSTED: &[&str] = &[
        "%windir%",
        r"\windows\system32\",
        r"\windows\syswow64\",
        r"c:\windows\",
        r"\program files\",
        r"\program files (x86)\",
    ];
    TRUSTED.iter().any(|p| run_lower.contains(p))
}

fn task_finding(name: &str, run: &str, hint: &str, score: u8) -> Finding {
    Finding::new(
        "scheduled task",
        &format!("task `{name}`"),
        &format!("action matches a known abuse pattern ({hint})"),
        score,
    )
    .evidence(format!("runs: {run}"))
    .recommend("`remove` will unregister this task")
}

/// Minimal CSV row splitter that respects double-quoted fields. schtasks does
/// not embed escaped quotes, so this stays simple.
fn parse_csv_row(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut start = 0;
    let mut in_quotes = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                out.push(line[start..i].trim_matches('"'));
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(line[start..].trim_matches('"'));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_fields_with_commas() {
        let row = parse_csv_row(r#""TaskName","Next Run Time","Status","C:\app.exe arg1,arg2""#);
        assert_eq!(row, vec!["TaskName", "Next Run Time", "Status", r"C:\app.exe arg1,arg2"]);
    }

    #[test]
    fn handles_plain_row() {
        assert_eq!(parse_csv_row("a,b,c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn windows_builtin_hidden_window_is_not_flagged() {
        // The real-world false positive: Windows' own SMBv1 cleanup task.
        let run = r"%windir%\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -NonInteractive -NoProfile -WindowStyle Hidden -File %windir%\system32\WindowsPowerShell\v1.0\Modules\SmbShare\DisableUnusedSmb1.ps1 -Scenario Client";
        assert!(classify_task(r"\Microsoft\Windows\SMB\UninstallSMB1ClientTask", run).is_none());
    }

    #[test]
    fn program_files_hidden_window_is_not_flagged() {
        // A legit installed app's updater running hidden — common and benign.
        let run = r"C:\Program Files\SomeApp\updater.exe -windowstyle hidden";
        assert!(classify_task(r"\SomeApp Update", run).is_none());
    }

    #[test]
    fn hidden_window_from_temp_flags_high() {
        let run = r"powershell.exe -WindowStyle Hidden -File C:\Users\x\AppData\Local\Temp\evil.ps1";
        let f = classify_task(r"\Evil", run).expect("should flag");
        assert!(f.score >= 60, "temp execution is HIGH, got {}", f.score);
    }

    #[test]
    fn encoded_command_flags_high_even_from_system32() {
        let run = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -EncodedCommand ZQBjAGgAbwA=";
        let f = classify_task(r"\X", run).expect("should flag");
        assert!(f.score >= 60, "encoded payload is HIGH, got {}", f.score);
    }

    #[test]
    fn hidden_window_from_untrusted_path_is_medium() {
        let run = r"C:\Users\x\AppData\Roaming\thing\run.exe -windowstyle hidden";
        let f = classify_task(r"\Thing", run).expect("should flag");
        assert!((35..60).contains(&f.score), "expected MEDIUM, got {}", f.score);
    }
}
