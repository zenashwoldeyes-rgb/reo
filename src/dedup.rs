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

/// Find duplicate files under the roots. Two-pass: group by size (cheap), then
/// SHA-256 only the same-size candidates (so we hash almost nothing unnecessary).
pub fn find_duplicates(roots: &[PathBuf]) -> Report {
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

    let mut by_hash: HashMap<(u64, String), Vec<PathBuf>> = HashMap::new();
    for (size, paths) in by_size {
        if paths.len() < 2 {
            continue; // unique size ⇒ can't be a duplicate
        }
        for p in paths {
            if let Some(h) = hash_file(&p) {
                by_hash.entry((size, h)).or_default().push(p);
            }
        }
    }

    let mut groups: Vec<DupGroup> = by_hash
        .into_iter()
        .filter(|(_, ps)| ps.len() > 1)
        .map(|((size, _), paths)| DupGroup { size, paths })
        .collect();
    // Biggest waste first.
    groups.sort_by(|a, b| {
        (b.size * (b.paths.len() as u64 - 1)).cmp(&(a.size * (a.paths.len() as u64 - 1)))
    });
    Report { scanned, groups }
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

        let report = find_duplicates(&[base.clone()]);
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
