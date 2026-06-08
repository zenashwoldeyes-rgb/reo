//! Scheduled-task surface. Tasks are a favorite persistence and "living off the
//! land" mechanism. We enumerate them via schtasks and flag actions that run
//! interpreters with encoded payloads or launch from transient directories.

use super::capture;
use super::types::{Finding, ScanReport};

const SUSPECT_HINTS: &[&str] = &[
    r"\appdata\local\temp",
    r"\temp\",
    r"\downloads\",
    "powershell -enc",
    "-encodedcommand",
    "-w hidden",
    "-windowstyle hidden",
    "mshta",
    "bitsadmin",
    "certutil -urlcache",
];

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
        let lower = run.to_lowercase();
        if let Some(hint) = SUSPECT_HINTS.iter().find(|h| lower.contains(**h)) {
            report.add(
                Finding::new(
                    "scheduled task",
                    &format!("task `{name}`"),
                    &format!("action matches a known abuse pattern ({hint})"),
                    60,
                )
                .evidence(format!("runs: {run}"))
                .recommend("`remove` will unregister this task"),
            );
        }
    }

    report.note_section("scheduled tasks", &format!("{total} tasks enumerated"));
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
    use super::parse_csv_row;

    #[test]
    fn splits_quoted_fields_with_commas() {
        let row = parse_csv_row(r#""TaskName","Next Run Time","Status","C:\app.exe arg1,arg2""#);
        assert_eq!(row, vec!["TaskName", "Next Run Time", "Status", r"C:\app.exe arg1,arg2"]);
    }

    #[test]
    fn handles_plain_row() {
        assert_eq!(parse_csv_row("a,b,c"), vec!["a", "b", "c"]);
    }
}
