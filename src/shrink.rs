//! File shrinking — REO's free hook.
//!
//! This is the one thing REO does that has nothing to do with a license: anyone
//! can shrink files, all locally, no account, no upload. PNGs are optimized
//! losslessly in place (pixels unchanged, still a usable .png); everything else
//! is compressed to a `.gz` sidecar. Like every other REO feature, nothing
//! leaves the machine.

use crate::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct ShrinkResult {
    pub input: PathBuf,
    pub output: PathBuf,
    pub method: &'static str,
    pub before: u64,
    pub after: u64,
}

impl ShrinkResult {
    /// Percent saved (0.0 if the file couldn't be made smaller).
    pub fn saved_pct(&self) -> f64 {
        if self.before == 0 {
            return 0.0;
        }
        let saved = self.before.saturating_sub(self.after) as f64;
        saved / self.before as f64 * 100.0
    }
}

/// Formats that are already compressed — gzip buys little, so we say so.
const PRECOMPRESSED: &[&str] = &[
    "jpg", "jpeg", "gif", "webp", "mp3", "mp4", "mov", "avi", "mkv", "zip", "gz", "7z", "rar",
    "xz", "bz2", "docx", "xlsx", "pptx", "pdf",
];

pub fn is_precompressed(ext: &str) -> bool {
    PRECOMPRESSED.contains(&ext)
}

/// Shrink one file. Returns the result, or an error the caller can surface.
pub fn shrink_file(path: &Path, max: bool) -> Result<ShrinkResult> {
    if !path.is_file() {
        return Err(format!("{} is not a file", path.display()).into());
    }
    let bytes = std::fs::read(path)?;
    let before = bytes.len() as u64;
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if ext == "png" {
        return shrink_png(path, &bytes, before);
    }
    if max {
        shrink_brotli(path, &bytes, before)
    } else {
        shrink_gzip(path, &bytes, before)
    }
}

/// Maximum lossless compression with Brotli (quality 11) to a `.br` sidecar.
/// Compresses *compressible* data better than gzip; like every lossless codec,
/// it can't shrink already-compressed media (that's physics, not a setting).
fn shrink_brotli(path: &Path, bytes: &[u8], before: u64) -> Result<ShrinkResult> {
    let out = append_ext(path, "br");
    let mut compressed: Vec<u8> = Vec::new();
    {
        // quality 11 (max), window 22.
        let mut w = brotli::CompressorWriter::new(&mut compressed, 4096, 11, 22);
        w.write_all(bytes)?;
    }
    let after = compressed.len() as u64;
    std::fs::write(&out, &compressed)?;
    Ok(ShrinkResult {
        input: path.to_path_buf(),
        output: out,
        method: "brotli (max)",
        before,
        after,
    })
}

/// Lossless PNG optimization, written back in place when it actually helps.
fn shrink_png(path: &Path, bytes: &[u8], before: u64) -> Result<ShrinkResult> {
    let opts = oxipng::Options::from_preset(4);
    let optimized = oxipng::optimize_from_memory(bytes, &opts)
        .map_err(|e| format!("png optimize failed: {e}"))?;
    let after = optimized.len() as u64;

    if after < before {
        std::fs::write(path, &optimized)?;
    }
    Ok(ShrinkResult {
        input: path.to_path_buf(),
        output: path.to_path_buf(),
        method: "png lossless",
        before,
        // If optimization didn't help, the file on disk is unchanged.
        after: after.min(before),
    })
}

/// Universal lossless compression to a `.gz` sidecar. Original is untouched.
fn shrink_gzip(path: &Path, bytes: &[u8], before: u64) -> Result<ShrinkResult> {
    let out = append_ext(path, "gz");
    let mut enc = GzEncoder::new(Vec::new(), Compression::best());
    enc.write_all(bytes)?;
    let compressed = enc.finish()?;
    let after = compressed.len() as u64;
    std::fs::write(&out, &compressed)?;
    Ok(ShrinkResult {
        input: path.to_path_buf(),
        output: out,
        method: "gzip",
        before,
        after,
    })
}

/// Aggregate result of shrinking a whole folder.
pub struct DirShrinkResult {
    pub scanned: u64,
    pub optimized: u64,
    pub before: u64,
    pub after: u64,
}

impl DirShrinkResult {
    pub fn saved(&self) -> u64 {
        self.before.saturating_sub(self.after)
    }
}

/// Recursively optimize every PNG under `dir` losslessly, in place. Other files
/// are left untouched (no `.gz` sidecars littering the folder). Returns the
/// aggregate so the caller can report total space reclaimed.
pub fn shrink_dir(dir: &Path) -> Result<DirShrinkResult> {
    let mut pngs: Vec<PathBuf> = Vec::new();
    // walk_user skips node_modules/build/hidden dirs so we never rewrite
    // dependency or VCS assets.
    crate::housekeeping::walk_user(dir, 16, &mut |path, _len| {
        if is_png(path) {
            pngs.push(path.to_path_buf());
        }
    });

    let mut res = DirShrinkResult {
        scanned: pngs.len() as u64,
        optimized: 0,
        before: 0,
        after: 0,
    };
    for path in pngs {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let before = bytes.len() as u64;
        res.before += before;
        match shrink_png(&path, &bytes, before) {
            Ok(r) => {
                res.after += r.after;
                if r.after < before {
                    res.optimized += 1;
                }
            }
            // Couldn't optimize this one — count it at its original size.
            Err(_) => res.after += before,
        }
    }
    Ok(res)
}

fn is_png(path: &Path) -> bool {
    path.extension()
        .map(|e| e.eq_ignore_ascii_case("png"))
        .unwrap_or(false)
}

/// Count the PNGs (and their total size) across the user's media folders —
/// used to show "found N images" before `shrink --all` touches anything.
pub fn count_pngs_all() -> (u64, u64) {
    let mut files = 0u64;
    let mut bytes = 0u64;
    for root in crate::housekeeping::media_roots() {
        crate::housekeeping::walk_user(&root, 16, &mut |path, len| {
            if is_png(path) {
                files += 1;
                bytes += len;
            }
        });
    }
    (files, bytes)
}

/// Optimize every PNG across the user's media folders losslessly, in place —
/// the "free GBs across my whole computer" mode. Aggregates all roots.
pub fn shrink_all() -> DirShrinkResult {
    let mut agg = DirShrinkResult {
        scanned: 0,
        optimized: 0,
        before: 0,
        after: 0,
    };
    for root in crate::housekeeping::media_roots() {
        if let Ok(r) = shrink_dir(&root) {
            agg.scanned += r.scanned;
            agg.optimized += r.optimized;
            agg.before += r.before;
            agg.after += r.after;
        }
    }
    agg
}

fn append_ext(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

/// Human-friendly byte size, e.g. 845K, 1.2M.
pub fn human(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes}{}", UNITS[0])
    } else {
        format!("{size:.1}{}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_sizes() {
        assert_eq!(human(512), "512B");
        assert_eq!(human(1024), "1.0K");
        assert_eq!(human(1_572_864), "1.5M");
    }

    #[test]
    fn precompressed_detection() {
        assert!(is_precompressed("jpg"));
        assert!(is_precompressed("mp4"));
        assert!(!is_precompressed("txt"));
        assert!(!is_precompressed("png")); // png has its own lossless path
    }

    #[test]
    fn gzip_shrinks_compressible_data() {
        let dir = std::env::temp_dir().join(format!("reo-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("repeat.txt");
        std::fs::write(&f, "A".repeat(10_000)).unwrap();
        let r = shrink_file(&f, false).unwrap();
        assert_eq!(r.method, "gzip");
        assert!(r.after < r.before);
        assert!(r.saved_pct() > 90.0, "got {:.1}%", r.saved_pct());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn brotli_max_compresses_text() {
        let dir = std::env::temp_dir().join(format!("reo-br-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("t.txt");
        std::fs::write(&f, "the quick brown fox jumps. ".repeat(2000)).unwrap();
        let r = shrink_file(&f, true).unwrap();
        assert_eq!(r.method, "brotli (max)");
        assert!(r.after < r.before, "brotli should shrink text");
        assert!(r.output.extension().is_some_and(|e| e == "br"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
