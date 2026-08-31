mod walker;
mod db;
mod classifier;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use db::ScanDb;
use classifier::Classifier;
use walker::{scan_tree, ScanEntry, ScanProgress};

/// Component-aware prefix match (walker::has_prefix_component equivalent).
fn has_prefix_component(p: &str, prefix: &str) -> bool {
    p == prefix
        || (p.len() > prefix.len() && p.as_bytes()[prefix.len()] == b'/' && p.starts_with(prefix))
}

#[derive(Parser)]
#[command(name = "wsl-scanner", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        #[arg(long, value_delimiter = ',')]
        paths: Vec<PathBuf>,

        #[arg(long)]
        quick: bool,

        #[arg(long = "db", default_value = "/tmp/wsl-master/cache/scan_cache.db")]
        db_path: PathBuf,

        #[arg(long, default_value = "/opt/wsl-master/config/default_rules.yaml")]
        rules: PathBuf,

        #[arg(long, default_value = "5")]
        timeout: u64,

        #[arg(long)]
        max_depth: Option<usize>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { paths, quick, db_path, rules, timeout, max_depth } => {
            let scan_id = format!("scan_{}", chrono::Local::now().format("%Y%m%d_%H%M%S"));

            let scan_paths: Vec<PathBuf> = if quick {
                vec![
                    PathBuf::from("/var/cache/apt"),
                    PathBuf::from("/var/log"),
                    PathBuf::from("/tmp"),
                    PathBuf::from(shellexpand::tilde("~/.cache").into_owned()),
                    PathBuf::from(shellexpand::tilde("~/.local/share/Trash").into_owned()),
                ]
            } else if !paths.is_empty() {
                paths
            } else {
                vec![PathBuf::from("/")]
            };

            let exclude_dirs: &[&str] = &["/proc", "/sys", "/dev", "/run", "/mnt"];

            let parent = db_path.parent().unwrap_or_else(|| Path::new("."));
            fs::create_dir_all(parent)?;

            let scan_db = ScanDb::open(&db_path, &scan_id)?;
            scan_db.clear_scan()?;

            let classifier = Arc::new(Classifier::from_yaml(&rules).unwrap_or_else(|e| {
                eprintln!("Warning: cannot load rules {:?}: {}", rules, e);
                Classifier {
                    prefix_rules: vec![],
                    pattern_rules: vec![],
                }
            }));

            let (tx_entry, rx_entry) = mpsc::sync_channel::<ScanEntry>(10_000);
            let (tx_progress, rx_progress) = mpsc::sync_channel::<ScanProgress>(100);

            let tx_entry_scan = tx_entry.clone();
            let tx_progress_scan = tx_progress.clone();

            // Set by the aggregator watchdog so the walker aborts promptly
            // instead of walking the rest of the tree into a dead channel.
            let stop = Arc::new(AtomicBool::new(false));
            let stop_scan = stop.clone();

            let scan_paths_clone = scan_paths.clone();
            let scan_handle = thread::spawn(move || {
                    let mut grand_total_files: u64 = 0;
                    let mut grand_total_bytes: u64 = 0;
                    let mut grand_total_skipped: u64 = 0;

                    for root in &scan_paths_clone {
                        if stop_scan.load(Ordering::Relaxed) {
                            break;
                        }
                        if !root.exists() {
                            eprintln!("Path does not exist: {:?}", root);
                            continue;
                        }
                        let root_str = root.to_string_lossy();
                        if exclude_dirs.iter().any(|e| has_prefix_component(&root_str, e)) {
                            continue;
                        }
                        match scan_tree(root, tx_entry_scan.clone(), tx_progress_scan.clone(), timeout, exclude_dirs, max_depth, &stop_scan) {
                            Ok((f, b, s)) => {
                                grand_total_files += f;
                                grand_total_bytes += b;
                                grand_total_skipped += s;
                            }
                            Err(e) => {
                                eprintln!("Scan error for {:?}: {}", root, e);
                            }
                        }
                    }

                    let _ = tx_progress_scan.send(ScanProgress {
                        msg_type: "done".into(),
                        scanned: grand_total_files,
                        total_bytes: grand_total_bytes,
                        current: String::new(),
                        timeout: None,
                    });

                    (grand_total_files, grand_total_bytes, grand_total_skipped)
            });

            // Drop our sender copies so rx_entry/rx_progress see Disconnected
            // when the scan thread finishes and drops its copies.
            drop(tx_entry);
            drop(tx_progress);

            let db = Arc::new(std::sync::Mutex::new(scan_db));
            let db_agg = db.clone();
            let classifier_agg = classifier.clone();
            let stop_agg = stop.clone();

            let aggregator_handle = thread::spawn(move || {
                let mut all_nodes: Vec<(String, String, String, i64, i64, i64, i64, i64, String, String, f64)> = vec![];
                let mut files_buf: Vec<(String, i64, String, String, String, f64)> = Vec::with_capacity(1000);
                // node_map: path -> (cumulative_file_size, file_count, dir_count)
                let mut node_map: HashMap<String, (i64, i64, i64)> = HashMap::new();
                let mut total_dirs: i64 = 0;
                let mut total_file_bytes: i64 = 0;
                let mut total_file_count: i64 = 0;
                let mut done = false;
                let mut last_activity = Instant::now();

                let flush_files = |buf: &mut Vec<(String, i64, String, String, String, f64)>, db: &Arc<std::sync::Mutex<ScanDb>>| {
                    if buf.is_empty() { return; }
                    match db.lock() {
                        Ok(db_lock) => {
                            if let Err(e) = db_lock.insert_files_batch(buf) {
                                eprintln!("Error writing files batch: {}", e);
                            }
                        }
                        Err(e) => eprintln!("Error locking DB for files: {}", e),
                    }
                    buf.clear();
                };

                loop {
                    while let Ok(prog) = rx_progress.try_recv() {
                        last_activity = Instant::now();
                        let json = serde_json::to_string(&prog).unwrap();
                        println!("{}", json);
                        if prog.msg_type == "done" {
                            done = true;
                        }
                    }

                    let entry_result = if done {
                        rx_entry.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected)
                    } else {
                        rx_entry.recv_timeout(Duration::from_millis(100))
                    };

                    match entry_result {
                        Ok(entry) => {
                            last_activity = Instant::now();
                            let path_str = entry.path.to_string_lossy().to_string();
                            let parent_path = entry.path
                                .parent()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default();
                            let name = entry.path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default();
                            let depth = entry.depth as i64;
                            let size = entry.size as i64;
                            let mtime = entry.mtime as f64;

                            let (cat, safety) = classifier_agg.classify(&path_str);

                            if entry.is_dir {
                                total_dirs += 1;
                                node_map.entry(parent_path.clone()).or_insert((0, 0, 0)).2 += 1;
                                node_map.entry(path_str.clone()).or_insert((0, 0, 0));

                                all_nodes.push((
                                    path_str, name, parent_path, depth,
                                    0, 0, 0, 0, cat, safety, mtime,
                                ));
                            } else {
                                total_file_count += 1;
                                total_file_bytes += size;

                                let p = node_map.entry(parent_path.clone()).or_insert((0, 0, 0));
                                p.0 += size;
                                p.1 += 1;

                                files_buf.push((
                                    path_str, size, parent_path, cat, safety, mtime,
                                ));
                                if files_buf.len() >= 1000 {
                                    flush_files(&mut files_buf, &db_agg);
                                }
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if !done && last_activity.elapsed().as_secs() >= timeout {
                                eprintln!("Scan timed out: no activity for {}s", timeout);
                                stop_agg.store(true, Ordering::Relaxed);
                                break;
                            }
                            continue;
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }

                // Flush remaining files
                flush_files(&mut files_buf, &db_agg);

                // Drain any remaining progress messages
                while let Ok(prog) = rx_progress.try_recv() {
                    println!("{}", serde_json::to_string(&prog).unwrap());
                }

                // Update node entries with accumulated values from node_map
                for node in &mut all_nodes {
                    if let Some((size, files, dirs)) = node_map.get(&node.0) {
                        node.5 = *size;
                        node.6 = *files;
                        node.7 = *dirs;
                    }
                }

                // Bottom-up size propagation
                let mut sorted_nodes = all_nodes.clone();
                sorted_nodes.sort_by_key(|n| -n.3); // depth desc
                for node in &sorted_nodes {
                    let parent = node.2.clone();
                    if parent.is_empty() { continue; }
                    if let Some((csize, cfiles, cdirs)) = node_map.get(&node.0) {
                        let (csize, cfiles, cdirs) = (*csize, *cfiles, *cdirs);
                        if let Some((psize, pfiles, pdirs)) = node_map.get_mut(&parent) {
                            *psize += csize;
                            *pfiles += cfiles;
                            *pdirs += cdirs;
                        }
                    }
                }
                // Re-apply updated node_map values
                for node in &mut all_nodes {
                    if let Some((size, files, dirs)) = node_map.get(&node.0) {
                        node.5 = *size;
                        node.6 = *files;
                        node.7 = *dirs;
                    }
                }

                // Write nodes to DB in batches
                for chunk in all_nodes.chunks(500) {
                    match db_agg.lock() {
                        Ok(db_lock) => {
                            if let Err(e) = db_lock.insert_nodes_batch(chunk) {
                                eprintln!("Error writing nodes batch: {}", e);
                            }
                        }
                        Err(e) => eprintln!("Error locking DB for nodes: {}", e),
                    }
                }

                (total_dirs, total_file_bytes, total_file_count)
            });

            let (scan_files, scan_bytes, scan_skipped) = scan_handle.join().unwrap();
            let (total_dirs, agg_bytes, agg_files) = aggregator_handle.join().unwrap();

            if let Ok(db_lock) = db.lock() {
                let _ = db_lock.finish_scan(agg_bytes, agg_files, total_dirs, scan_skipped as i64);
            }

            let done_msg = serde_json::json!({
                "type": "done",
                "scan_id": scan_id,
                "total_files": scan_files,
                "total_dirs": total_dirs,
                "total_size": scan_bytes,
                "skipped": scan_skipped
            });
            println!("{}", serde_json::to_string(&done_msg).unwrap());
        }
    }

    Ok(())
}
