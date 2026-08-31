"""SQLite cache query layer — read-only interface for scan results."""

import os
import sqlite3
import threading
from typing import Optional

# Keep in sync with scanner/src/db.rs. Applied idempotently so the Python
# side (and the Python fallback scanner) works on a fresh database before
# the Rust scanner has ever run.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    total_size INTEGER DEFAULT 0,
    total_files INTEGER DEFAULT 0,
    total_dirs INTEGER DEFAULT 0,
    skipped INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    parent_path TEXT DEFAULT '',
    depth INTEGER DEFAULT 0,
    is_dir INTEGER DEFAULT 0,
    size_self INTEGER DEFAULT 0,
    size_total INTEGER DEFAULT 0,
    file_count INTEGER DEFAULT 0,
    dir_count INTEGER DEFAULT 0,
    category TEXT DEFAULT '',
    safety TEXT DEFAULT 'Safe',
    mtime REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_nodes_scan_path ON nodes(scan_id, path);
CREATE INDEX IF NOT EXISTS idx_nodes_scan_parent ON nodes(scan_id, parent_path);
CREATE INDEX IF NOT EXISTS idx_nodes_scan_parent_size ON nodes(scan_id, parent_path, size_total DESC);
CREATE INDEX IF NOT EXISTS idx_nodes_scan_depth_size ON nodes(scan_id, depth, size_total DESC);
CREATE INDEX IF NOT EXISTS idx_nodes_scan_size ON nodes(scan_id, size_total DESC);
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER DEFAULT 0,
    parent_path TEXT NOT NULL,
    category TEXT DEFAULT '',
    safety TEXT DEFAULT 'Safe',
    mtime REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_files_scan_parent ON files(scan_id, parent_path);
CREATE INDEX IF NOT EXISTS idx_files_scan_parent_size ON files(scan_id, parent_path, size DESC);
CREATE INDEX IF NOT EXISTS idx_files_scan_size ON files(scan_id, size DESC);
CREATE INDEX IF NOT EXISTS idx_files_scan_category ON files(scan_id, category);
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    name TEXT NOT NULL,
    size INTEGER DEFAULT 0,
    file_count INTEGER DEFAULT 0,
    dir_count INTEGER DEFAULT 0
);
"""


# Schema creation is serialized and done at most once per db path per
# process: running DDL on every new connection needlessly contends for the
# database write lock ( CREATE TABLE IF NOT EXISTS still starts a write
# transaction), which matters now that the web server is threaded.
_SCHEMA_LOCK = threading.Lock()
_SCHEMA_DONE: set[str] = set()

# DISTINCT category over a large files table walks the whole category index
# (~1s on 300k rows); the result only changes when a new scan lands, so it is
# memoized per (db_path, scan_id) for the life of the process.
_DISTINCT_CAT_CACHE: dict[tuple[str, str], list[str]] = {}
_DISTINCT_CAT_LOCK = threading.Lock()


def distinct_file_categories(
    conn: sqlite3.Connection, scan_id: str, db_path: str = ""
) -> list[str]:
    key = (db_path, scan_id)
    with _DISTINCT_CAT_LOCK:
        cached = _DISTINCT_CAT_CACHE.get(key)
    if cached is not None:
        return cached
    cats = [
        r[0] for r in conn.execute(
            "SELECT DISTINCT category FROM files WHERE scan_id = ? AND category != ''",
            (scan_id,),
        )
    ]
    with _DISTINCT_CAT_LOCK:
        _DISTINCT_CAT_CACHE[key] = cats
        # keep the cache bounded
        if len(_DISTINCT_CAT_CACHE) > 16:
            for k in list(_DISTINCT_CAT_CACHE)[:-16]:
                _DISTINCT_CAT_CACHE.pop(k, None)
    return cats


class ScanStore:
    """Read scan results from SQLite."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            parent = os.path.dirname(self.db_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.execute("PRAGMA journal_mode=WAL")
            with _SCHEMA_LOCK:
                if self.db_path not in _SCHEMA_DONE:
                    have = conn.execute(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
                        "AND name IN ('scans','nodes','files','categories')"
                    ).fetchone()[0]
                    if have < 4:
                        conn.executescript(_SCHEMA)
                    conn.commit()
                    _SCHEMA_DONE.add(self.db_path)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def list_scans(self) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT scan_id, total_size, total_files, total_dirs, skipped, created_at "
            "FROM scans ORDER BY created_at DESC LIMIT 20"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_latest_scan_id(self) -> Optional[str]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT scan_id FROM scans ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return row["scan_id"] if row else None

    def get_scan_info(self, scan_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_nodes(
        self, scan_id: str, parent_path: Optional[str] = None, top_n: int = 100
    ) -> list[dict]:
        """Get directory-level nodes, optionally filtered by parent."""
        conn = self._get_conn()
        if parent_path is not None:
            rows = conn.execute(
                "SELECT * FROM nodes WHERE scan_id = ? AND parent_path = ? "
                "ORDER BY size_total DESC LIMIT ?",
                (scan_id, parent_path, top_n),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM nodes WHERE scan_id = ? AND depth = 0 "
                "ORDER BY size_total DESC LIMIT ?",
                (scan_id, top_n),
            ).fetchall()
            if not rows:
                rows = conn.execute(
                    "SELECT * FROM nodes WHERE scan_id = ? "
                    "ORDER BY size_total DESC LIMIT ?",
                    (scan_id, top_n),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_files(
        self, scan_id: str, parent_path: str, top_n: int = 200
    ) -> list[dict]:
        """Get files within a directory."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM files WHERE scan_id = ? AND parent_path = ? "
            "ORDER BY size DESC LIMIT ?",
            (scan_id, parent_path, top_n),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_categories(self, scan_id: str) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM categories WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    def get_tree(
        self, scan_id: str, parent_path: Optional[str] = None,
        max_depth: int = 5, top_n: int = 50, max_nodes: int = 8000
    ) -> list[dict]:
        """Get nested tree structure — single-pass batch queries, no recursion."""
        import os
        conn = self._get_conn()

        if parent_path is not None:
            pd_row = conn.execute(
                "SELECT depth FROM nodes WHERE scan_id = ? AND path = ?",
                (scan_id, parent_path)
            ).fetchone()
            parent_depth = pd_row["depth"] if pd_row else 0
            pp = parent_path
        else:
            parent_depth = -1
            pp = ''

        max_abs_depth = parent_depth + max_depth + 2

        # ── 1 query: all dirs in depth range (subtree-filtered when entering a dir) ──
        if pp:
            pp_like = pp.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '/%'
            dir_rows = conn.execute(
                "SELECT * FROM nodes WHERE scan_id = ? AND (path = ? OR path LIKE ? ESCAPE '\\')"
                " AND depth > ? AND depth <= ? "
                "ORDER BY parent_path, size_total DESC",
                (scan_id, pp, pp_like, parent_depth, max_abs_depth)
            ).fetchall()
        else:
            dir_rows = conn.execute(
                "SELECT * FROM nodes WHERE scan_id = ? AND depth > ? AND depth <= ? "
                "ORDER BY parent_path, size_total DESC",
                (scan_id, parent_depth, max_abs_depth)
            ).fetchall()

        dirs_by_parent: dict[str, list[dict]] = {}
        root_dirs: list[dict] = []
        for r in dir_rows:
            pp_key = r["parent_path"]
            if pp_key not in dirs_by_parent:
                dirs_by_parent[pp_key] = []
            bucket = dirs_by_parent[pp_key]
            if len(bucket) < top_n:
                d = dict(r)
                bucket.append(d)
                if parent_path is None and d["depth"] == 0:
                    root_dirs.append(d)

        root_dirs.sort(key=lambda d: d["size_total"], reverse=True)
        root_dirs = root_dirs[:top_n]

        # ── Batch files only for dirs that survive the top_n cap ──
        # (dir_rows is uncapped; fetching files for dropped dirs wastes most of
        # the query time on big scans — dirs_by_parent holds exactly the kept ones)
        all_dir_paths = {d["path"] for kept in dirs_by_parent.values() for d in kept}
        all_dir_paths.add(pp)
        files_by_parent: dict[str, list[dict]] = {}
        path_list = list(all_dir_paths)
        # Per-directory top-N files. Two strategies:
        #  - small parent set: plain IN (...) — cheapest to prepare
        #  - large parent set: temp table + correlated top-N subquery that
        #    reads exactly top_n index entries per directory. A giant IN list
        #    makes SQLite prepare-time explode, and a ROW_NUMBER() window is
        #    ~2x slower because it enumerates every file before filtering.
        if path_list:
            if len(path_list) <= 300:
                placeholders = ','.join(['?'] * len(path_list))
                file_rows = conn.execute(
                    "SELECT f.path, f.size, f.category, f.safety, f.parent_path"
                    " FROM files f"
                    " WHERE f.scan_id = ? AND f.parent_path IN (" + placeholders + ")"
                    "   AND f.rowid IN (SELECT x.rowid FROM files x"
                    "     WHERE x.scan_id = ? AND x.parent_path = f.parent_path"
                    "     ORDER BY x.size DESC LIMIT ?)",
                    (scan_id, *path_list, scan_id, top_n),
                ).fetchall()
            else:
                conn.execute(
                    "CREATE TEMP TABLE IF NOT EXISTS _want_parents (parent_path TEXT PRIMARY KEY)"
                )
                conn.execute("DELETE FROM _want_parents")
                conn.executemany(
                    "INSERT OR IGNORE INTO _want_parents VALUES (?)",
                    [(p,) for p in path_list],
                )
                file_rows = conn.execute(
                    "SELECT f.path, f.size, f.category, f.safety, f.parent_path"
                    " FROM _want_parents w CROSS JOIN files f"
                    " ON f.scan_id = ? AND f.parent_path = w.parent_path"
                    " AND f.rowid IN (SELECT x.rowid FROM files x"
                    "   WHERE x.scan_id = ? AND x.parent_path = w.parent_path"
                    "   ORDER BY x.size DESC LIMIT ?)",
                    (scan_id, scan_id, top_n),
                ).fetchall()
            for fr in file_rows:
                fp = fr["parent_path"]
                if fp not in files_by_parent:
                    files_by_parent[fp] = []
                files_by_parent[fp].append(dict(fr))
            for lst in files_by_parent.values():
                lst.sort(key=lambda f: f.get("size", 0), reverse=True)

        # ── Build tree in memory ──
        _cnt = [0]

        def _make_file_node(fp: str, pp: str, fr: dict, display_parent: str = "") -> dict:
            fn = os.path.basename(fr.get("path", ""))
            _cnt[0] += 1
            return {
                "path": fr.get("path", fp), "parent_path": pp, "name": fn,
                "is_dir": 0, "size_total": fr.get("size", 0), "size_self": fr.get("size", 0),
                "file_count": 0, "dir_count": 0,
                "category": fr.get("category", ""),
                "safety": fr.get("safety", "Safe"),
                "depth": parent_depth + 1, "_is_file": True,
                "_display_parent": display_parent or pp,
            }

        def collect_deep_files(dir_path: str, depth_left: int, limit: int, root_path: str = "") -> list[dict]:
            if not root_path:
                root_path = dir_path
            result: list[dict] = []
            for fr in files_by_parent.get(dir_path, [])[:limit]:
                result.append(_make_file_node(fr.get("path", ""), dir_path, fr, root_path))
                if len(result) >= limit:
                    return result
            if depth_left > 0:
                for d in dirs_by_parent.get(dir_path, [])[:limit]:
                    sub = collect_deep_files(d["path"], depth_left - 1, limit - len(result), root_path)
                    result.extend(sub)
                    if len(result) >= limit:
                        break
            return result

        def build(pp_key: str, depth_remaining: int, limit: int) -> list[dict]:
            truncated = _cnt[0] >= max_nodes and depth_remaining < max_depth

            # 1. Get all directories and files separately
            dirs = root_dirs if (pp_key == '' and parent_path is None) else dirs_by_parent.get(pp_key, [])
            files = files_by_parent.get(pp_key, [])

            # 2. Prioritize directories. Files are sorted and truncated if necessary.
            result: list[dict] = []
            for d in dirs:
                d["_children"] = []
                d["_is_file"] = False
                result.append(d)

            files.sort(key=lambda f: f.get("size", 0), reverse=True)
            remaining_limit = limit - len(result)
            if remaining_limit > 0:
                for fr in files[:remaining_limit]:
                    fname = os.path.basename(fr.get("path", ""))
                    node = {
                        "path": fr.get("path", ""), "parent_path": pp_key, "name": fname,
                        "is_dir": 0, "size_total": fr.get("size", 0), "size_self": fr.get("size", 0),
                        "file_count": 0, "dir_count": 0, "category": fr.get("category", ""),
                        "safety": fr.get("safety", "Safe"), "depth": parent_depth + 1,
                        "_is_file": True, "_children": []
                    }
                    _cnt[0] += 1
                    result.append(node)
            
            result.sort(key=lambda x: x.get("size_total", 0), reverse=True)

            if truncated:
                return result

            # 3. Second pass: populate children for directories in the result list
            dirs_in_result = [n for n in result if not n.get("_is_file") and n["is_dir"] and (n["dir_count"] > 0 or n["file_count"] > 0)]
            if dirs_in_result:
                total_size = sum(n.get("size_total", 0) for n in dirs_in_result) or 1
                for n in dirs_in_result:
                    remaining = max_nodes - _cnt[0]
                    ratio = n.get("size_total", 0) / total_size
                    sub_limit = max(3, min(50, int(remaining * ratio))) if remaining > 0 else 3
                    if depth_remaining > 1:
                        n["_children"] = build(n["path"], depth_remaining - 1, sub_limit)
                    else:
                        n["_children"] = collect_deep_files(n["path"], 20, sub_limit)

            return result

        return build(pp, max_depth, max_nodes)
