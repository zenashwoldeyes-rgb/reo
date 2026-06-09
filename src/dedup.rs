//! Duplicate-file finder — the real way to reclaim space "everywhere". Finds
//! byte-for-byte identical files and (on request) removes the redundant copies,
//! always keeping one. All local. Bounded by reality, unlike a certain fictional
//! TV "middle-out" compressor: it frees the space duplicates waste, no more.

use crate::housekeeping;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

pub struct DupGroup {
    pub size: u64,
    pub paths: Vec<PathBuf>,
}

pub struct Report {
    pub scanned: u64,
    pub groups: Vec<DupGroup>,
}

impl Report {
    /// Bytes wasted by redundant copies (each group keeps one).
    pub fn wasted_bytes(&self) -> u64 {
        self.groups.iter().map(|g| g.size * (g.paths.len() as u64 - 1)).sum()
    }
    pub fn redundant_files(&self) -> u64 {
        self.groups.iter().map(|g| g.paths.len() as u64 - 1).sum()
    }
}

/// Find duplicate files under the roots. Three tiers, each cheaper-first so we
/// read as little as possible:
///   1. group by size (no reads),
///   2. quick-hash the first 8 KB of same-size files (tiny reads),
///   3. full SHA-256 only files that also collide on that prefix (the real dups).
/// `progress(phase, done, total)` drives the live spinner in the CLI.
pub fn find_duplicates(roots: &[PathBuf], mut progress: impl FnMut(&str, usize, usize)) -> Report {
    progress("scanning", 0, 0);
    let mut by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
    let mut scanned = 0u64;
    for root in roots {
        housekeeping::walk_user(root, 12, &mut |p, len| {
            if len > 0 {
                scanned += 1;
                by_size.entry(len).or_default().push(p.to_path_buf());
            }
        });
    }

    // Candidates: only files that share a size with another file.
    let candidates: Vec<(u64, PathBuf)> = by_size
        .into_iter()
        .filter(|(_, ps)| ps.len() > 1)
        .flat_map(|(size, ps)| ps.into_iter().map(move |p| (size, p)))
        .collect();
    let total = candidates.len();

    // Tier 2: cheap 8 KB prefix hash.
    let mut by_quick: HashMap<(u64, String), Vec<PathBuf>> = HashMap::new();
    for (i, (size, p)) in candidates.into_iter().enumerate() {
        progress("hashing", i + 1, total);
        if let Some(qh) = quick_hash(&p) {
            by_quick.entry((size, qh)).or_default().push(p);
        }
    }

    // Tier 3: full hash only the prefix-collision groups.
    let mut by_full: HashMap<(u64, String), Vec<PathBuf>> = HashMap::new();
    for ((size, _), paths) in by_quick {
        if paths.len() < 2 {
            continue;
        }
        for p in paths {
            if let Some(fh) = hash_file(&p) {
                by_full.entry((size, fh)).or_default().push(p);
            }
        }
    }

    let mut groups: Vec<DupGroup> = by_full
        .into_iter()
        .filter(|(_, ps)| ps.len() > 1)
        .map(|((size, _), paths)| DupGroup { size, paths })
        .collect();
    groups.sort_by(|a, b| {
        (b.size * (b.paths.len() as u64 - 1)).cmp(&(a.size * (a.paths.len() as u64 - 1)))
    });
    Report { scanned, groups }
}

/// Hash just the first 8 KB — a fast pre-filter so we never fully read files
/// that obviously differ.
fn quick_hash(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; 8192];
    let n = f.read(&mut buf).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&buf[..n]);
    Some(format!("{:x}", hasher.finalize()))
}

fn hash_file(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

/// Remove redundant copies, keeping the first file in each group. Best effort.
/// Returns (files_removed, bytes_freed).
pub fn dedupe(report: &Report) -> (u64, u64) {
    let mut removed = 0u64;
    let mut freed = 0u64;
    for g in &report.groups {
        for p in g.paths.iter().skip(1) {
            if std::fs::remove_file(p).is_ok() {
                removed += 1;
                freed += g.size;
            }
        }
    }
    (removed, freed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_and_removes_duplicates_keeping_one() {
        let base = std::env::temp_dir().join(format!("reo-dedup-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        // Two identical files + one unique.
        std::fs::write(base.join("a.bin"), b"the very same bytes here").unwrap();
        std::fs::write(base.join("copy-of-a.bin"), b"the very same bytes here").unwrap();
        std::fs::write(base.join("different.bin"), b"totally different content!").unwrap();

        let report = find_duplicates(&[base.clone()], |_, _, _| {});
        assert_eq!(report.groups.len(), 1, "exactly one duplicate set");
        assert_eq!(report.redundant_files(), 1, "one redundant copy");

        let (removed, _) = dedupe(&report);
        assert_eq!(removed, 1);
        // One of the identical pair remains; the unique file is untouched.
        let remaining = [base.join("a.bin"), base.join("copy-of-a.bin")]
            .iter()
            .filter(|p| p.exists())
            .count();
        assert_eq!(remaining, 1, "kept exactly one copy");
        assert!(base.join("different.bin").exists(), "unique file untouched");

        let _ = std::fs::remove_dir_all(&base);
    }
}
