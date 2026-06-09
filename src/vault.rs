//! Pre-encryption vault — keep clean copies of your files so ransomware can't
//! take them. You snapshot a folder while it's healthy; if an attack later
//! encrypts it, you restore the clean copies. All local — the vault lives under
//! REO's data dir on this machine.

use crate::housekeeping;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone)]
pub struct SnapshotMeta {
    pub id: String,
    pub source: PathBuf,
    pub taken: String,
    pub files: u64,
    pub bytes: u64,
}

/// Snapshot the current (clean) contents of `source` into the vault. Skips
/// dependency/build/hidden noise (same pruning as the rest of REO).
pub fn snapshot(source: &Path, vault_root: &Path) -> Result<SnapshotMeta> {
    if !source.is_dir() {
        return Err(format!("{} is not a folder", source.display()).into());
    }
    let id = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let files_dir = vault_root.join(&id).join("files");
    std::fs::create_dir_all(&files_dir)?;

    let mut paths: Vec<(PathBuf, u64)> = Vec::new();
    housekeeping::walk_user(source, 24, &mut |p, len| paths.push((p.to_path_buf(), len)));

    let mut files = 0u64;
    let mut bytes = 0u64;
    for (path, len) in paths {
        if let Ok(rel) = path.strip_prefix(source) {
            let target = files_dir.join(rel);
            if let Some(parent) = target.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::copy(&path, &target).is_ok() {
                files += 1;
                bytes += len;
            }
        }
    }

    let meta = SnapshotMeta {
        id,
        source: source.to_path_buf(),
        taken: chrono::Utc::now().to_rfc3339(),
        files,
        bytes,
    };
    std::fs::write(
        vault_root.join(&meta.id).join("manifest.json"),
        serde_json::to_vec_pretty(&meta)?,
    )?;
    Ok(meta)
}

/// All snapshots, newest first.
pub fn list(vault_root: &Path) -> Vec<SnapshotMeta> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(vault_root) {
        for e in entries.flatten() {
            if let Ok(bytes) = std::fs::read(e.path().join("manifest.json")) {
                if let Ok(meta) = serde_json::from_slice::<SnapshotMeta>(&bytes) {
                    out.push(meta);
                }
            }
        }
    }
    out.sort_by(|a, b| b.id.cmp(&a.id));
    out
}

/// Restore the most recent snapshot taken of `source` back into it (overwriting
/// encrypted/changed files with the clean copies). Returns (files, bytes).
pub fn restore_latest(vault_root: &Path, source: &Path) -> Result<(u64, u64)> {
    let snap = list(vault_root)
        .into_iter()
        .find(|m| m.source == source)
        .ok_or_else(|| format!("no snapshot found for {}", source.display()))?;
    let files_dir = vault_root.join(&snap.id).join("files");

    let mut items: Vec<PathBuf> = Vec::new();
    collect(&files_dir, &mut items);

    let mut restored = 0u64;
    let mut bytes = 0u64;
    for vpath in items {
        if let Ok(rel) = vpath.strip_prefix(&files_dir) {
            let target = source.join(rel);
            if let Some(parent) = target.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(n) = std::fs::copy(&vpath, &target) {
                restored += 1;
                bytes += n;
            }
        }
    }
    Ok((restored, bytes))
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect(&p, out);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_then_restore_recovers_encrypted_files() {
        let base = std::env::temp_dir().join(format!("reo-vault-{}", std::process::id()));
        let work = base.join("docs");
        let vault = base.join("vault");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join("a.txt"), b"the original clean contents").unwrap();
        std::fs::write(work.join("b.txt"), b"another important file").unwrap();

        // Snapshot the clean folder.
        let meta = snapshot(&work, &vault).unwrap();
        assert_eq!(meta.files, 2);

        // "Ransomware" encrypts both files.
        std::fs::write(work.join("a.txt"), b"\x00\xff\x91\x3e ENCRYPTED garbage").unwrap();
        std::fs::write(work.join("b.txt"), b"\x12\x9a\x44 ENCRYPTED garbage").unwrap();
        assert!(std::fs::read(work.join("a.txt")).unwrap().starts_with(b"\x00\xff"));

        // Restore from the vault.
        let (restored, _) = restore_latest(&vault, &work).unwrap();
        assert_eq!(restored, 2);
        assert_eq!(std::fs::read(work.join("a.txt")).unwrap(), b"the original clean contents");
        assert_eq!(std::fs::read(work.join("b.txt")).unwrap(), b"another important file");

        let _ = std::fs::remove_dir_all(&base);
    }
}
