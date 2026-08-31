use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, UNIX_EPOCH};
use walkdir::WalkDir;

/// A single scan result for a file or directory.
#[derive(Debug, Clone)]
pub struct ScanEntry {
    pub path: PathBuf,
    pub size: u64,
    pub is_dir: bool,
    pub mtime: i64,
    pub depth: usize,
}

/// Progress update sent during scanning.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanProgress {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub scanned: u64,
    pub total_bytes: u64,
    pub current: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<bool>,
}

/// Component-aware prefix match: "/tmp" matches "/tmp" and "/tmp/foo"
/// but must NOT swallow "/tmpfoo". Allocation-free for the hot loop.
fn has_prefix_component(p: &str, prefix: &str) -> bool {
    p == prefix
        || (p.len() > prefix.len()
            && p.as_bytes()[prefix.len()] == b'/'
            && p.starts_with(prefix))
}

/// Scan a directory tree. Hang protection is handled by a watchdog
/// in the aggregator (main.rs), not per-file threads.
/// Returns entries via channel and progress via progress channel.
/// `stop` is set by the aggregator's watchdog so the walk aborts
/// promptly instead of continuing to walk (with failing sends) after
/// aggregation has already given up.
#[allow(clippy::too_many_arguments)]
pub fn scan_tree(
    root: &Path,
    tx_entries: mpsc::SyncSender<ScanEntry>,
    tx_progress: mpsc::SyncSender<ScanProgress>,
    _timeout_secs: u64,
    exclude_prefixes: &[&str],
    max_depth: Option<usize>,
    stop: &AtomicBool,
) -> Result<(u64, u64, u64)> {
    let mut total_files: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut skipped: u64 = 0;
    let root_str = root.to_string_lossy().to_string();
    let mut last_progress = Instant::now();

    for entry in WalkDir::new(root)
        .follow_links(false)
        // NOTE: no sort_by_file_name — sorting forces WalkDir to buffer and
        // sort every directory listing, which measurably slows big scans
        // (~20-40% on a 300k-file tree).
        .into_iter()
        .filter_entry(|e| {
            // Prune (don't just skip) beyond max_depth so WalkDir does not
            // keep traversing directories it will never yield.
            if let Some(md) = max_depth {
                if e.depth() > md {
                    return false;
                }
            }
            let p = e.path().to_string_lossy();
            !exclude_prefixes
                .iter()
                .any(|prefix| has_prefix_component(p.as_ref(), prefix))
        })
    {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                skipped += 1;
                let _ = tx_progress.send(ScanProgress {
                    msg_type: "timeout".into(),
                    scanned: total_files,
                    total_bytes,
                    current: format!("{}/<error: {}>", root_str, e),
                    timeout: Some(true),
                });
                continue;
            }
        };

        let is_dir = entry.file_type().is_dir();
        let depth = entry.depth();
        let path = entry.path().to_path_buf();

        let (size, mtime) = if is_dir {
            (0, 0)
        } else {
            match entry.metadata() {
                Ok(m) => {
                    let mtime = m
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    (m.len(), mtime)
                }
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            }
        };

        if !is_dir {
            total_files += 1;
            total_bytes += size;
        }

        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();

        let _ = tx_entries.send(ScanEntry {
            path: path.clone(),
            size,
            is_dir,
            mtime,
            depth,
        });

        // Send progress every 500ms (time-based, not count-based)
        if last_progress.elapsed() >= Duration::from_millis(500) {
            last_progress = Instant::now();
            let _ = tx_progress.send(ScanProgress {
                msg_type: "progress".into(),
                scanned: total_files,
                total_bytes,
                current: relative,
                timeout: None,
            });
        }
    }

    Ok((total_files, total_bytes, skipped))
}
