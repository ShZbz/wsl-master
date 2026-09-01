"""Scanner controller — manage Rust scanner subprocess."""

import json
import os
import stat
import subprocess
import threading
import logging
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Callable
from wsl_master.config import DEFAULT_DB_PATH, DEFAULT_RULES_PATH, DEFAULT_SCANNER_PATH

logger = logging.getLogger("wsl_master.scan")

# Roots pruned during walks (mirrors the Rust scanner's exclude list).
EXCLUDE_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/mnt")


def _is_excluded(p: str, prefixes: tuple[str, ...] = EXCLUDE_PREFIXES) -> bool:
    # Component-aware prefix match: "/tmp" must not swallow "/tmpfoo"
    return any(p == e or p.startswith(e + "/") for e in prefixes)


def _dedup_roots(paths: list[str]) -> list[str]:
    """Drop duplicate and nested roots — walking an overlap double-counts
    every file under it (e.g. scanning both / and /home)."""
    unique = sorted(set(paths))
    kept: list[str] = []
    for p in unique:
        if not any(p == q or p.startswith(q + "/") for q in unique if q != p):
            kept.append(p)
    return kept


class ScanState(Enum):
    IDLE = "idle"
    SCANNING = "scanning"
    DONE = "done"
    ERROR = "error"


@dataclass
class ScanStatus:
    state: ScanState = ScanState.IDLE
    scan_id: str = ""
    progress: int = 0
    total_files: int = 0
    total_size: int = 0
    current_path: str = ""
    skipped: int = 0
    error: str = ""

    @property
    def running(self) -> bool:
        return self.state == ScanState.SCANNING


class ScanController:
    """Manages a Rust wsl-scanner process."""

    def __init__(
        self,
        scanner_path: str = DEFAULT_SCANNER_PATH,
        db_path: str = DEFAULT_DB_PATH,
        rules_path: str = DEFAULT_RULES_PATH,
    ):
        self.scanner_path = scanner_path
        self.db_path = db_path
        self.rules_path = rules_path
        self.status = ScanStatus()
        self._process: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._on_progress: Optional[Callable[[dict], None]] = None
        self._on_done: Optional[Callable[[dict], None]] = None
        # Set by stop() so the Python fallback walk (which has no subprocess
        # to terminate) aborts like the Rust scanner does.
        self._stop_flag = threading.Event()

    def _build_args(self, mode: str, paths: Optional[list[str]]) -> list[str]:
        """Build the wsl-scanner argv. Paths are passed as repeated --paths
        flags — the previous ','.join() corrupted paths containing commas."""
        args = [self.scanner_path, "scan", "--db", self.db_path, "--rules", self.rules_path]
        if mode == "quick":
            args.append("--quick")
        elif paths:
            for p in paths:
                args.extend(["--paths", p])
        return args

    def start(
        self,
        mode: str = "quick",
        paths: Optional[list[str]] = None,
        on_progress: Optional[Callable[[dict], None]] = None,
        on_done: Optional[Callable[[dict], None]] = None,
    ):
        """Start scanning."""
        if self.status.running:
            logger.warning("Scan already running, ignoring start request")
            return
        self._on_progress = on_progress
        self._on_done = on_done
        self._stop_flag.clear()
        self.status = ScanStatus(state=ScanState.SCANNING)
        logger.info(f"Starting {mode} scan, paths={paths}")
        self._thread = threading.Thread(
            target=self._run, args=(mode, paths), daemon=True
        )
        self._thread.start()

    def stop(self):
        """Stop scanning."""
        self.status.state = ScanState.IDLE
        self._stop_flag.set()
        logger.info("Stopping scan")
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
        self._cleanup_aborted_scan()

    def _cleanup_aborted_scan(self):
        """Remove the all-zero placeholder row an aborted scan leaves behind.

        clear_scan() inserts it at scan start; if the scanner is killed before
        finish_scan() it stays in `scans` as the newest entry, so every
        latest-scan lookup returns an empty scan and the UI goes blank.
        """
        try:
            from wsl_master.cache.store import ScanStore
            store = ScanStore(self.db_path)
            conn = store._get_conn()
            conn.execute(
                "DELETE FROM scans WHERE total_size = 0 AND total_files = 0 AND total_dirs = 0"
            )
            conn.commit()
        except Exception:
            logger.debug("aborted-scan cleanup skipped", exc_info=True)

    def _emit_progress(self, data: dict):
        if self._on_progress:
            try:
                self._on_progress(data)
            except Exception:
                # A misbehaving callback must not abort the scan loop.
                logger.warning("on_progress callback failed", exc_info=True)

    def _emit_done(self, data: dict):
        if self._on_done:
            try:
                self._on_done(data)
            except Exception:
                logger.warning("on_done callback failed", exc_info=True)

    def _run(self, mode: str, paths: Optional[list[str]]):
        scanner = self.scanner_path
        # Fallback: if Rust binary not found, try in PATH
        if not os.path.exists(scanner):
            scanner = "wsl-scanner"

        args = self._build_args(mode, paths)
        args[0] = scanner

        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        try:
            self._process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            # Drain stderr immediately to prevent buffer-full blocking
            self._stderr_lines = []
            def _drain_stderr():
                for line in self._process.stderr:
                    self._stderr_lines.append(line)
            threading.Thread(target=_drain_stderr, daemon=True).start()

            for line in self._process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                msg_type = data.get("type", "")
                if msg_type == "progress":
                    self.status.current_path = data.get("current", "")
                    self.status.total_files = data.get("scanned", 0)
                    self.status.total_size = data.get("total_bytes", 0)
                    self.status.progress = min(50, self.status.progress + 1)  # active indicator
                    self._emit_progress(data)
                elif msg_type == "done":
                    scan_id = data.get("scan_id", "")
                    if scan_id:
                        self.status.scan_id = scan_id
                        self.status.state = ScanState.DONE
                    self.status.total_files = data.get("total_files", data.get("scanned", 0))
                    self.status.total_size = data.get("total_size", data.get("total_bytes", 0))
                    self.status.skipped = data.get("skipped", 0)
                    self.status.progress = 100
                    self._emit_done(data)
                    if scan_id:
                        break
                elif msg_type == "timeout":
                    self.status.skipped += 1
                    self._emit_progress(data)

            # No timeout here: the Rust scanner may spend well over 5s in
            # finish_scan's wal_checkpoint(TRUNCATE) on large databases, which
            # previously turned a successful scan into a spurious ERROR state.
            self._process.wait()

            # Print collected stderr lines
            for line in self._stderr_lines:
                print(line, end="")

        except FileNotFoundError:
            self._python_fallback(mode, paths)
        except Exception as e:
            self.status.error = str(e)
            self.status.state = ScanState.ERROR
            logger.error(f"Scan failed: {e}")
        finally:
            if self.status.state == ScanState.SCANNING:
                self.status.state = ScanState.DONE

    def _python_fallback(self, mode: str, paths: Optional[list[str]]):
        """Fallback scanner using os.walk when Rust binary is unavailable."""
        import os
        from datetime import datetime
        from wsl_master.cache.store import ScanStore
        from wsl_master.rules.engine import RulesEngine

        self.status.error = "FALLBACK: using Python scanner (slower)"
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.status.scan_id = scan_id

        store = ScanStore(self.db_path)
        rules_engine = RulesEngine.from_default()

        if mode == "quick":
            scan_paths = [
                "/var/cache/apt", "/var/log", "/tmp",
                os.path.expanduser("~/.cache"),
                os.path.expanduser("~/.local/share/Trash"),
            ]
        elif paths:
            # Skip roots under excluded prefixes, matching the Rust scanner —
            # walking into /mnt over 9p would effectively hang the scan.
            valid = [
                p.rstrip("/") or "/" for p in paths
                if os.path.exists(p) and not _is_excluded(p.rstrip("/"))
            ]
            scan_paths = _dedup_roots(valid)
        else:
            scan_paths = ["/"]

        total_files = 0
        total_bytes = 0
        # path -> {"size_self": direct file bytes, "size_total": propagated total, ...}
        node_map = {}
        files_data = []

        conn = store._get_conn()
        # DELETE the scans row first: two scans in the same second share a
        # scan_id, and the bare INSERT below raised IntegrityError (UNIQUE).
        conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM nodes WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM files WHERE scan_id = ?", (scan_id,))
        conn.execute(
            "INSERT INTO scans (scan_id, total_size, total_files, total_dirs, skipped) "
            "VALUES (?, 0, 0, 0, 0)", (scan_id,)
        )
        conn.commit()

        stopped = False
        for root_path in scan_paths:
            if stopped:
                break
            if not os.path.isdir(root_path):
                continue
            for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
                if self._stop_flag.is_set():
                    stopped = True
                    break
                if dirpath != root_path and _is_excluded(dirpath):
                    dirnames[:] = []
                    continue

                parent_dir = os.path.dirname(dirpath)
                depth = dirpath.rstrip(os.sep).count(os.sep) - root_path.rstrip(os.sep).count(os.sep)
                node_map[dirpath] = {
                    "size_self": 0, "size_total": 0, "file_count": 0, "dir_count": 0,
                    "parent": parent_dir if parent_dir != dirpath else "",
                    "depth": max(0, depth),
                }

                # Register this dir under its parent (count 1 per dir, not children)
                if parent_dir != dirpath and parent_dir in node_map:
                    node_map[parent_dir]["dir_count"] += 1

                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    try:
                        st = os.lstat(fpath)
                        # Single stat: classify off the lstat mode itself.
                        # os.path.isfile() would stat a second time (and
                        # follow symlinks). Symlinks count as files with the
                        # link's own size, matching the Rust scanner.
                        if not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                            continue
                        size = st.st_size
                        mtime = int(st.st_mtime)
                    except OSError:
                        continue

                    cat, safety = rules_engine.classify(fpath, size)
                    total_files += 1
                    total_bytes += size

                    node_map[dirpath]["size_self"] += size
                    node_map[dirpath]["file_count"] += 1

                    files_data.append((scan_id, fpath, size, dirpath, cat, safety, float(mtime)))
                    if len(files_data) >= 1000:
                        conn.executemany(
                            "INSERT INTO files (scan_id, path, size, parent_path, category, safety, mtime) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)", files_data
                        )
                        files_data.clear()

                    if total_files % 100 == 0:
                        if self._stop_flag.is_set():
                            stopped = True
                            break
                        self.status.total_files = total_files
                        self.status.total_size = total_bytes
                        self.status.current_path = fpath
                        self._emit_progress({
                            "type": "progress", "scanned": total_files,
                            "total_bytes": total_bytes, "current": fpath[:60],
                        })

        # Flush remaining files
        if files_data:
            conn.executemany(
                "INSERT INTO files (scan_id, path, size, parent_path, category, safety, mtime) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)", files_data
            )

        if stopped:
            # Discard the partial scan: rollback uncommitted rows and drop
            # the all-zero placeholder so latest-scan lookups stay valid.
            conn.rollback()
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
            self.status.state = ScanState.IDLE
            return

        # Bottom-up size propagation: accumulate into size_total, keep size_self
        # as the directory's own direct file bytes (matches the Rust scanner's schema).
        # Deepest-first order guarantees a child's subtree total is complete
        # before it is folded into its parent.
        sorted_paths = sorted(node_map.keys(), key=lambda p: -p.rstrip(os.sep).count(os.sep))
        for dpath in sorted_paths:
            info = node_map[dpath]
            info["size_total"] += info["size_self"]
            parent = info["parent"]
            if parent and parent in node_map:
                node_map[parent]["size_total"] += info["size_total"]
                node_map[parent]["file_count"] += info["file_count"]
                node_map[parent]["dir_count"] += info["dir_count"]

        # Write nodes
        nodes_data = []
        for dpath, info in node_map.items():
            name = os.path.basename(dpath) or dpath
            cat, safety = rules_engine.classify(dpath, 0)
            nodes_data.append((
                scan_id, dpath, name, info["parent"], info["depth"],
                info["size_self"], info["size_total"], info["file_count"], info["dir_count"],
                cat, safety, 0.0
            ))
            if len(nodes_data) >= 500:
                conn.executemany(
                    "INSERT INTO nodes (scan_id, path, name, parent_path, depth, is_dir, "
                    "size_self, size_total, file_count, dir_count, category, safety, mtime) "
                    "VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)", nodes_data
                )
                nodes_data.clear()

        if nodes_data:
            conn.executemany(
                "INSERT INTO nodes (scan_id, path, name, parent_path, depth, is_dir, "
                "size_self, size_total, file_count, dir_count, category, safety, mtime) "
                "VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)", nodes_data
            )

        conn.execute(
            "UPDATE scans SET total_size = ?, total_files = ?, total_dirs = ?, skipped = 0 WHERE scan_id = ?",
            (total_bytes, total_files, len(node_map), scan_id),
        )
        # Commit everything: without this the open transaction was invisible
        # to every other connection and rolled back on process exit, i.e. the
        # whole fallback scan silently produced NO data.
        conn.commit()

        self.status.total_files = total_files
        self.status.total_size = total_bytes
        self.status.progress = 100
        self.status.state = ScanState.DONE

        self._emit_done({
            "type": "done", "scan_id": scan_id,
            "total_files": total_files, "total_size": total_bytes,
        })

    def get_status(self) -> dict:
        return {
            "state": self.status.state.value,
            "running": self.status.running,
            "scan_id": self.status.scan_id,
            "progress": self.status.progress,
            "total_files": self.status.total_files,
            "total_size": self.status.total_size,
            "current_path": self.status.current_path,
            "skipped": self.status.skipped,
            "error": self.status.error,
        }
