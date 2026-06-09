//! Plain-English file finding and safe disk cleanup — the "make my computer
//! cleaner, smaller, and searchable" surface. Everything is local; cleanup shows
//! what it will reclaim first and only deletes well-known temporary files.

use std::path::{Path, PathBuf};

/// Recursively visit files under `root` (depth-limited), calling `f(path, size)`
/// for each regular file. Symlinks are skipped (no loops) and unreadable
/// directories are silently passed over — best effort.
pub(crate) fn walk(root: &Path, max_depth: usize, f: &mut dyn FnMut(&Path, u64)) {
    fn inner(dir: &Path, depth: usize, max: usize, f: &mut dyn FnMut(&Path, u64)) {
        if depth > max {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                inner(&path, depth + 1, max, f);
            } else if ft.is_file() {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                f(&path, size);
            }
        }
    }
    inner(root, 0, max_depth, f);
}

/// Directory names that are dependency/build/system noise — never what a person
/// means when they search for "my files". Pruned from user searches.
const NOISE_DIRS: &[&str] = &[
    "node_modules", "venv", "site-packages", "__pycache__", "target", "dist", "build", "vendor",
    "bin", "obj", "out", ".cache", ".gradle",
];

/// Like `walk`, but for *user* files: prunes dependency/build folders and
/// hidden (dot) directories so it only sees files people actually own. Used by
/// both `find` and `shrink --all` (so we never touch node_modules assets).
pub(crate) fn walk_user(root: &Path, max_depth: usize, f: &mut dyn FnMut(&Path, u64)) {
    fn inner(dir: &Path, depth: usize, max: usize, f: &mut dyn FnMut(&Path, u64)) {
        if depth > max {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                let name = entry.file_name().to_string_lossy().to_lowercase();
                if name.starts_with('.') || NOISE_DIRS.contains(&name.as_str()) {
                    continue;
                }
                inner(&path, depth + 1, max, f);
            } else if ft.is_file() {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                f(&path, size);
            }
        }
    }
    inner(root, 0, max_depth, f);
}

// ---------------------------------------------------------------------------
// find — search your folders in plain English
// ---------------------------------------------------------------------------

pub struct Hit {
    pub path: PathBuf,
    pub bytes: u64,
}

/// Words to strip from a "find …" phrase so "find my big resume file" searches
/// for just "big" and "resume".
const FIND_STOPWORDS: &[&str] = &[
    "find", "search", "for", "my", "the", "a", "an", "file", "files", "where", "is", "are",
    "named", "name", "called", "with", "that", "on", "in", "computer", "please", "locate", "show",
    "me", "any", "all", "of", "and", "to",
];

/// Extract the meaningful search keywords from a natural-language query.
pub fn keywords(query: &str) -> Vec<String> {
    query
        .split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '_' && c != '-')
                .to_lowercase()
        })
        .filter(|w| w.len() >= 2 && !FIND_STOPWORDS.contains(&w.as_str()))
        .collect()
}

/// Search the user's common folders for files whose name contains any keyword.
/// Read-only; results sorted largest-first and capped.
pub fn find(query: &str) -> Vec<Hit> {
    let keys = keywords(query);
    let mut hits = Vec::new();
    if keys.is_empty() {
        return hits;
    }
    for root in search_roots() {
        walk_user(&root, 6, &mut |path, bytes| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if keys.iter().any(|k| name.contains(k)) {
                hits.push(Hit {
                    path: path.to_path_buf(),
                    bytes,
                });
            }
        });
    }
    hits.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    hits.truncate(50);
    hits
}

/// Folders where images typically live — the targets for `shrink --all`.
pub fn media_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = dirs::home_dir() {
        for sub in ["Pictures", "Desktop", "Downloads", "Documents"] {
            let p = home.join(sub);
            if p.is_dir() {
                roots.push(p);
            }
        }
    }
    roots
}

/// The folders we search by default — the places people actually keep things.
fn search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = dirs::home_dir() {
        for sub in ["Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music"] {
            let p = home.join(sub);
            if p.is_dir() {
                roots.push(p);
            }
        }
        if roots.is_empty() {
            roots.push(home);
        }
    }
    roots
}

// ---------------------------------------------------------------------------
// clean — reclaim disk space from temporary files
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Method {
    /// Delete the regular files inside the path.
    Files,
    /// Empty the OS Recycle Bin / Trash via the platform tool.
    RecycleBin,
}

pub struct Reclaimable {
    pub label: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub files: u64,
    method: Method,
}

/// Survey safe-to-delete locations (temp files, browser caches, the Recycle Bin)
/// and report how much space they hold. Does NOT delete anything.
pub fn scan_reclaimable() -> Vec<Reclaimable> {
    let mut out = Vec::new();
    for (label, dir) in reclaimable_dirs() {
        let (bytes, files) = dir_size(&dir);
        if files > 0 {
            out.push(Reclaimable {
                label,
                path: dir,
                bytes,
                files,
                method: Method::Files,
            });
        }
    }
    if let Some((bytes, files)) = recycle_bin_size() {
        if files > 0 {
            out.push(Reclaimable {
                label: "Recycle Bin".into(),
                path: recycle_bin_path(),
                bytes,
                files,
                method: Method::RecycleBin,
            });
        }
    }
    out
}

/// Reclaim space from the surveyed locations. Returns (bytes_freed,
/// files_removed). Best effort — files currently in use are skipped, not forced.
pub fn clean(targets: &[Reclaimable]) -> (u64, u64) {
    let mut freed = 0u64;
    let mut count = 0u64;
    for t in targets {
        match t.method {
            Method::RecycleBin => {
                let (b, f) = empty_recycle_bin();
                freed += b;
                count += f;
            }
            Method::Files => {
                let mut files: Vec<(PathBuf, u64)> = Vec::new();
                walk(&t.path, 8, &mut |p, b| files.push((p.to_path_buf(), b)));
                for (p, b) in files {
                    if std::fs::remove_file(&p).is_ok() {
                        freed += b;
                        count += 1;
                    }
                }
            }
        }
    }
    (freed, count)
}

/// Locations safe to clear: OS/user temp directories and browser caches (which
/// browsers transparently rebuild). Downloads is deliberately NOT included —
/// people keep things they want there; the biggest-files view surfaces those.
fn reclaimable_dirs() -> Vec<(String, PathBuf)> {
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    dirs.push(("Temporary files".into(), std::env::temp_dir()));
    if let Some(local) = dirs::data_local_dir() {
        let t = local.join("Temp");
        if t.is_dir() && t != std::env::temp_dir() {
            dirs.push(("App temp files".into(), t));
        }
        for (label, rel) in [
            ("Edge cache", "Microsoft/Edge/User Data/Default/Cache"),
            ("Chrome cache", "Google/Chrome/User Data/Default/Cache"),
        ] {
            let p = local.join(rel);
            if p.is_dir() {
                dirs.push((label.into(), p));
            }
        }
    }
    dirs.retain(|(_, p)| p.is_dir());
    dirs
}

fn recycle_bin_path() -> PathBuf {
    PathBuf::from(r"C:\$Recycle.Bin")
}

fn recycle_bin_size() -> Option<(u64, u64)> {
    let p = recycle_bin_path();
    if !p.is_dir() {
        return None;
    }
    Some(dir_size(&p))
}

/// Empty the Recycle Bin via PowerShell and report what it held. Windows-only;
/// a no-op elsewhere.
fn empty_recycle_bin() -> (u64, u64) {
    let (bytes, files) = recycle_bin_size().unwrap_or((0, 0));
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Clear-RecycleBin -Force -ErrorAction SilentlyContinue",
        ])
        .output();
    (bytes, files)
}

// ---------------------------------------------------------------------------
// space — what's eating the most disk
// ---------------------------------------------------------------------------

/// The biggest files across the user's content folders, largest first. Read-only
/// — the user decides what to delete.
pub fn biggest_files(limit: usize) -> Vec<Hit> {
    let mut all: Vec<Hit> = Vec::new();
    for root in search_roots() {
        walk_user(&root, 8, &mut |path, bytes| {
            all.push(Hit {
                path: path.to_path_buf(),
                bytes,
            });
        });
    }
    all.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    all.truncate(limit);
    all
}

fn dir_size(dir: &Path) -> (u64, u64) {
    let mut bytes = 0u64;
    let mut files = 0u64;
    walk(dir, 8, &mut |_p, b| {
        bytes += b;
        files += 1;
    });
    (bytes, files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keywords_drops_filler_words() {
        assert_eq!(keywords("find my resume file"), vec!["resume"]);
        assert_eq!(keywords("where are my vacation photos"), vec!["vacation", "photos"]);
        assert_eq!(keywords("find report.pdf"), vec!["report.pdf"]);
    }

    #[test]
    fn keywords_empty_for_only_fillers() {
        assert!(keywords("find my files").is_empty());
    }

    #[test]
    fn walk_finds_files_and_skips_depth() {
        let base = std::env::temp_dir().join(format!("reo-hk-{}", std::process::id()));
        let deep = base.join("a").join("b");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(base.join("top.txt"), b"hi").unwrap();
        std::fs::write(deep.join("buried.txt"), b"hello").unwrap();

        let mut shallow = 0;
        walk(&base, 0, &mut |_p, _b| shallow += 1);
        assert_eq!(shallow, 1, "depth 0 should only see the top file");

        let mut all = 0;
        walk(&base, 8, &mut |_p, _b| all += 1);
        assert_eq!(all, 2, "deep walk should see both files");

        let _ = std::fs::remove_dir_all(&base);
    }
}
