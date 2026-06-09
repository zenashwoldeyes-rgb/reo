//! On-device behavioral threat detection — content analysis, not signatures.
//!
//! Signature AV matches known-malware hashes (and misses anything new). The
//! `scan/` module flags suspicious process *names*. This module is different: it
//! reads file *content* and reasons about behavior, entirely locally — the same
//! technique cloud detectors use, with none of the data leaving the machine.
//!
//! Flagship detector: ransomware. Encryption has an unavoidable signature — it
//! turns structured files into near-random bytes. We catch that three ways:
//!   1. Entropy + format masquerade: a `.docx`/`.jpg`/`.txt` whose bytes are
//!      near-random AND whose magic header is wrong ⇒ it was encrypted in place.
//!   2. Known ransomware file extensions (`.locked`, `.crypt`, …).
//!   3. Ransom-note files left behind ("HOW_TO_DECRYPT…", "your files are
//!      encrypted").
//! `scan_ransomware` is the on-demand sweep; `watch` is the real-time daemon
//! that catches encryption *as it happens* via OS file-change events.

use crate::housekeeping;
use std::collections::VecDeque;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct Finding {
    pub path: PathBuf,
    pub reason: String,
    pub score: u8,
}

pub struct Report {
    pub scanned: u64,
    pub findings: Vec<Finding>,
}

impl Report {
    /// Overall risk = worst finding, nudged up as evidence stacks.
    pub fn score(&self) -> u8 {
        let max = self.findings.iter().map(|f| f.score).max().unwrap_or(0);
        let stack = (self.findings.len().saturating_sub(1) as u8).min(10);
        max.saturating_add(stack).min(100)
    }
}

/// Shannon entropy of a byte sample, in bits/byte (0.0–8.0). Encrypted and
/// compressed data sit near 8.0; text and structured documents far lower.
pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Known ransomware-appended file extensions (a strong, specific signal).
const RANSOM_EXTS: &[&str] = &[
    "locked", "crypt", "crypto", "encrypted", "enc", "wcry", "wncry", "locky", "cerber", "zepto",
    "odin", "aesir", "cryptolocker", "crab", "krab", "xtbl", "ecc", "ezz", "exx", "vault", "ryk",
    "ryuk", "conti", "lockbit",
];

/// Magic-byte prefixes for formats we can validate. If a file carries one of
/// these extensions but NOT its header, the content was replaced.
fn expected_magic(ext: &str) -> Option<&'static [u8]> {
    match ext {
        "jpg" | "jpeg" => Some(&[0xFF, 0xD8, 0xFF]),
        "png" => Some(&[0x89, 0x50, 0x4E, 0x47]),
        "gif" => Some(b"GIF8"),
        "pdf" => Some(b"%PDF"),
        "docx" | "xlsx" | "pptx" | "zip" | "jar" => Some(&[0x50, 0x4B, 0x03, 0x04]),
        _ => None,
    }
}

/// Extensions whose contents should be human-readable text (low entropy).
fn is_text_ext(ext: &str) -> bool {
    matches!(
        ext,
        "txt" | "csv" | "log" | "json" | "xml" | "html" | "htm" | "md" | "ini" | "yaml" | "yml"
            | "rtf" | "tex" | "srt" | "sql"
    )
}

/// True if `sample` (the first bytes of a file with extension `ext`) looks like
/// it was encrypted: near-random content where structure is expected.
fn looks_encrypted(ext: &str, sample: &[u8]) -> bool {
    if sample.len() < 64 {
        return false; // too small to judge
    }
    let h = entropy(sample);
    if let Some(magic) = expected_magic(ext) {
        // Structured binary: high entropy is normal *if* the header is intact.
        return h > 7.5 && !sample.starts_with(magic);
    }
    if is_text_ext(ext) {
        // Text should never be near-random.
        return h > 7.2;
    }
    false // unknown type: don't guess (avoid false positives)
}

/// Ransom-note filenames. Deliberately specific so ordinary `README.md` and the
/// like are never flagged.
fn is_ransom_note(name_lower: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "how_to_decrypt",
        "how to decrypt",
        "how_to_recover",
        "how to recover",
        "decrypt_instruction",
        "decryption_instruction",
        "recover_files",
        "restore_files",
        "your_files",
        "your files are encrypted",
        "files_encrypted",
        "_readme.txt",
        "readme_to_decrypt",
        "help_decrypt",
        "unlock_files",
        "ransom",
    ];
    NEEDLES.iter().any(|n| name_lower.contains(n))
}

fn read_sample(path: &Path, max: usize) -> std::io::Result<Vec<u8>> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; max];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// Behavioral ransomware sweep over the given roots. Read-only; analyzes a small
/// sample of each file's bytes. Prunes dependency/build/hidden folders.
pub fn scan_ransomware(roots: &[PathBuf]) -> Report {
    let mut report = Report {
        scanned: 0,
        findings: Vec::new(),
    };
    for root in roots {
        housekeeping::walk_user(root, 8, &mut |path, _len| {
            report.scanned += 1;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();

            if RANSOM_EXTS.contains(&ext.as_str()) {
                report.findings.push(Finding {
                    path: path.to_path_buf(),
                    reason: format!("known ransomware extension .{ext}"),
                    score: 92,
                });
                return;
            }
            if is_ransom_note(&name) {
                report.findings.push(Finding {
                    path: path.to_path_buf(),
                    reason: "looks like a ransom note left by malware".into(),
                    score: 70,
                });
                return;
            }
            if let Ok(sample) = read_sample(path, 8192) {
                if looks_encrypted(&ext, &sample) {
                    report.findings.push(Finding {
                        path: path.to_path_buf(),
                        reason: format!(
                            ".{ext} file with no valid header and near-random content (entropy {:.2}/8.0) — looks encrypted",
                            entropy(&sample)
                        ),
                        score: 82,
                    });
                }
            }
        });
    }
    report
}

// ---------------------------------------------------------------------------
// Real-time monitoring — catch encryption *as it happens*
// ---------------------------------------------------------------------------

/// Decide if a single just-changed file shows ransomware behavior. Returns the
/// reason, or `None`. Reuses the same content analysis as the on-demand sweep.
pub fn suspicious(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if RANSOM_EXTS.contains(&ext.as_str()) {
        return Some(format!("known ransomware extension .{ext}"));
    }
    if is_ransom_note(&name) {
        return Some("ransom note dropped".into());
    }
    let sample = read_sample(path, 8192).ok()?;
    if looks_encrypted(&ext, &sample) {
        return Some(format!(
            "contents went near-random (entropy {:.2}/8.0)",
            entropy(&sample)
        ));
    }
    None
}

/// Real-time ransomware monitor. Subscribes to OS file-change events on the
/// given roots (efficient — only changed files are inspected) and raises the
/// alarm when it sees the signature of an active attack: a burst of files
/// turning into encrypted content within a short window. Blocks until Ctrl-C.
///
/// `on_event` is invoked for each suspicious file (per-file notice); `on_alert`
/// fires once per attack when the burst threshold is crossed. The CLI passes UI
/// callbacks; tests pass counters.
pub fn watch(
    roots: &[PathBuf],
    mut on_event: impl FnMut(&Path, &str),
    mut on_alert: impl FnMut(usize),
) -> crate::Result<()> {
    use notify::{EventKind, RecursiveMode, Watcher};

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| format!("could not start the file watcher: {e}"))?;
    for root in roots {
        if root.is_dir() {
            watcher
                .watch(root, RecursiveMode::Recursive)
                .map_err(|e| format!("could not watch {}: {e}", root.display()))?;
        }
    }

    const WINDOW: Duration = Duration::from_secs(30);
    const THRESHOLD: usize = 8;
    let mut hits: VecDeque<Instant> = VecDeque::new();
    let mut recent: VecDeque<(PathBuf, Instant)> = VecDeque::new();
    let mut last_alert: Option<Instant> = None;

    loop {
        let event = match rx.recv() {
            Ok(Ok(ev)) => ev,
            Ok(Err(_)) => continue,
            Err(_) => break, // watcher dropped
        };
        if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            continue;
        }
        let now = Instant::now();
        for path in event.paths {
            if !path.is_file() {
                continue;
            }
            // Debounce: the OS fires several modify events per save.
            if recent
                .iter()
                .any(|(p, t)| *p == path && now.duration_since(*t) < Duration::from_secs(3))
            {
                continue;
            }
            recent.push_back((path.clone(), now));
            while recent.len() > 512 {
                recent.pop_front();
            }

            if let Some(reason) = suspicious(&path) {
                on_event(&path, &reason);
                hits.push_back(now);
                while hits.front().is_some_and(|t| now.duration_since(*t) > WINDOW) {
                    hits.pop_front();
                }
                if hits.len() >= THRESHOLD
                    && last_alert.is_none_or(|t| now.duration_since(t) > Duration::from_secs(15))
                {
                    last_alert = Some(now);
                    on_alert(hits.len());
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Process attribution + response — name (and stop) the culprit
// ---------------------------------------------------------------------------

/// The process most likely responsible for an encryption burst.
pub struct Culprit {
    pub pid: u32,
    pub name: String,
    pub exe: Option<PathBuf>,
    /// Bytes written during the ~0.7s attribution sample.
    pub written: u64,
}

/// Identify the process doing the mass-writing by sampling per-process disk I/O
/// over a short interval — the heaviest writer during an active attack is the
/// encryptor. Works without elevation for your own processes; reading system /
/// other-user processes' I/O needs Administrator. This is the practical stand-in
/// for kernel-ETW per-write attribution (which needs an admin kernel trace).
pub fn identify_culprit() -> Option<Culprit> {
    let mut sys = sysinfo::System::new_all();
    std::thread::sleep(Duration::from_millis(700));
    sys.refresh_all(); // written_bytes now holds the delta over the interval
    let me = sysinfo::get_current_pid().ok();
    sys.processes()
        .values()
        .filter(|p| Some(p.pid()) != me)
        .map(|p| (p, p.disk_usage().written_bytes))
        .filter(|(_, w)| *w > 0)
        .max_by_key(|(_, w)| *w)
        .map(|(p, w)| Culprit {
            pid: p.pid().as_u32(),
            name: p.name().to_string_lossy().into_owned(),
            exe: p.exe().map(|e| e.to_path_buf()),
            written: w,
        })
}

/// Terminate a process by PID. Returns true if the kill signal was sent.
pub fn terminate(pid: u32) -> bool {
    let sys = sysinfo::System::new_all();
    sys.processes()
        .values()
        .find(|p| p.pid().as_u32() == pid)
        .map(|p| p.kill())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes (LCG) — high entropy, like ciphertext.
    fn random_bytes(n: usize) -> Vec<u8> {
        let mut x: u64 = 0x9E3779B97F4A7C15;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (x >> 33) as u8
            })
            .collect()
    }

    #[test]
    fn entropy_distinguishes_text_from_random() {
        let text = b"the quick brown fox jumps over the lazy dog. ".repeat(20);
        assert!(entropy(&text) < 5.5, "text entropy was {}", entropy(&text));
        assert!(entropy(&random_bytes(4096)) > 7.8);
    }

    #[test]
    fn encrypted_text_file_is_flagged() {
        // A ".txt" full of random bytes ⇒ encrypted.
        assert!(looks_encrypted("txt", &random_bytes(4096)));
        // Real text ⇒ not flagged.
        let text = b"meeting notes: ship the release on friday. ".repeat(40);
        assert!(!looks_encrypted("txt", &text));
    }

    #[test]
    fn jpeg_with_valid_header_is_not_flagged_even_at_high_entropy() {
        // Real JPEGs are high-entropy but start with FF D8 FF — must NOT flag.
        let mut jpg = vec![0xFF, 0xD8, 0xFF, 0xE0];
        jpg.extend(random_bytes(4096));
        assert!(!looks_encrypted("jpg", &jpg));
        // A ".jpg" with random bytes and no header ⇒ encrypted.
        assert!(looks_encrypted("jpg", &random_bytes(4096)));
    }

    #[test]
    fn ransom_notes_match_but_readme_does_not() {
        assert!(is_ransom_note("how_to_decrypt_files.txt"));
        assert!(is_ransom_note("your files are encrypted.html"));
        assert!(!is_ransom_note("readme.md"));
        assert!(!is_ransom_note("changelog.txt"));
    }
}
