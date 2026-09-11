"""Regression tests for the v3.2.4 treemap rendering fixes.

Two user-visible defects are covered:

1. Nested mode drew "black blocks" — folders that arrived from /api/tree with no
   children at all, so the renderer had nothing to put inside the rectangle.
   Root cause was in ScanStore.get_tree: collect_deep_files can only walk
   dirs_by_parent, which is capped at the max_abs_depth window, so a folder whose
   files sit below that window came back empty.
2. Flat mode was a uniform near-black wall, because every folder was filled with
   one fixed colour regardless of what it held.
"""

import sqlite3
import pytest

from wsl_master.cache.store import ScanStore
from wsl_master.web.server import RequestHandler


@pytest.fixture
def deep_store(tmp_path):
    """A scan whose files sit several levels below the displayed depth.

    Mirrors the real layout that triggered the bug:
    <root>/.cache (d0) / uv (d1) / .tmpX (d2) / nvidia (d3) / cu13 (d4) /
    lib (d5) / *.so (files). A depth-3 view stops its dir window at depth 4, so
    cu13 has no reachable children and .tmpX came back empty.
    """
    db = tmp_path / "deep.db"
    conn = sqlite3.connect(str(db))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT UNIQUE, total_size INT, total_files INT, total_dirs INT,
            skipped INT, created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY, scan_id TEXT, path TEXT, name TEXT,
            parent_path TEXT, depth INT, is_dir INT, size_self INT,
            size_total INT, file_count INT, dir_count INT, category TEXT,
            safety TEXT, mtime REAL
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY, scan_id TEXT, path TEXT, size INT,
            parent_path TEXT, category TEXT, safety TEXT, mtime REAL
        );
        CREATE INDEX IF NOT EXISTS idx_nodes_scan_parent ON nodes(scan_id, parent_path);
        CREATE INDEX IF NOT EXISTS idx_files_scan_parent ON files(scan_id, parent_path);
        INSERT INTO scans VALUES ('scan_deep', 3000, 2, 6, 0, '2026-01-01');
    """)
    dirs = [
        ("/root/.cache", "/root", 0, 3000, 2, 5),
        ("/root/.cache/uv", "/root/.cache", 1, 3000, 2, 4),
        ("/root/.cache/uv/.tmpX", "/root/.cache/uv", 2, 3000, 2, 3),
        ("/root/.cache/uv/.tmpX/nvidia", "/root/.cache/uv/.tmpX", 3, 3000, 2, 2),
        ("/root/.cache/uv/.tmpX/nvidia/cu13", "/root/.cache/uv/.tmpX/nvidia", 4, 3000, 2, 1),
        ("/root/.cache/uv/.tmpX/nvidia/cu13/lib", "/root/.cache/uv/.tmpX/nvidia/cu13", 5, 3000, 2, 0),
    ]
    for i, (path, parent, depth, size, fc, dc) in enumerate(dirs, start=1):
        name = path.rsplit("/", 1)[-1]
        conn.execute(
            "INSERT INTO nodes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (i, "scan_deep", path, name, parent, depth, 1, 0, size, fc, dc, "", "Safe", 0),
        )
    # Both files live at depth 6 — below the dir window of a depth-3 view.
    conn.execute("INSERT INTO files VALUES (?,?,?,?,?,?,?,?)",
                 (1, "scan_deep", "/root/.cache/uv/.tmpX/nvidia/cu13/lib/a.so", 1800,
                  "/root/.cache/uv/.tmpX/nvidia/cu13/lib", "应用缓存", "Caution", 0))
    conn.execute("INSERT INTO files VALUES (?,?,?,?,?,?,?,?)",
                 (2, "scan_deep", "/root/.cache/uv/.tmpX/nvidia/cu13/lib/b.so", 1200,
                  "/root/.cache/uv/.tmpX/nvidia/cu13/lib", "应用缓存", "Caution", 0))
    conn.commit()
    conn.close()
    return ScanStore(str(db))


def _walk(nodes):
    for n in nodes:
        yield n
        yield from _walk(n.get("_children") or [])


def _childless_dirs(nodes):
    """Folders that carry size but arrived with nothing to draw inside."""
    return [
        n for n in _walk(nodes)
        if n.get("is_dir") and n.get("size_total", 0) > 0 and not n.get("_children")
        and (n.get("file_count") or n.get("dir_count"))
    ]


class TestChildlessFoldersAreBackfilled:
    def test_deep_files_reach_a_shallow_view(self, deep_store):
        # Before the fix .tmpX came back with _children == [] because its files
        # are two levels deeper than the query window.
        tree = deep_store.get_tree("scan_deep", max_depth=3, top_n=50, max_nodes=8000)
        assert _childless_dirs(tree) == []
        names = {n["name"] for n in _walk(tree) if not n.get("is_dir")}
        assert {"a.so", "b.so"} <= names

    def test_backfilled_file_has_display_parent(self, deep_store):
        # Clicking a backfilled file must navigate to the folder it is drawn in
        # rather than to its real (invisible) parent, which is not in the view.
        tree = deep_store.get_tree("scan_deep", max_depth=3, top_n=50, max_nodes=8000)
        files = [n for n in _walk(tree) if not n.get("is_dir")]
        assert files
        for f in files:
            assert f["_display_parent"]
            assert f["_display_parent"] in {n["path"] for n in _walk(tree)}

    def test_no_repeated_backfill_across_depths(self, deep_store):
        for depth in (1, 2, 3, 4, 5):
            tree = deep_store.get_tree("scan_deep", max_depth=depth, top_n=50, max_nodes=8000)
            assert _childless_dirs(tree) == [], f"depth={depth} left an empty folder"

    def test_genuinely_empty_folder_is_left_alone(self, tmp_path):
        # A folder with no files anywhere and zero size has nothing to show;
        # the backfill must not invent children or loop on it.
        db = tmp_path / "empty.db"
        conn = sqlite3.connect(str(db))
        conn.executescript("""
            CREATE TABLE scans (scan_id TEXT UNIQUE, total_size INT, total_files INT,
                                total_dirs INT, skipped INT, created_at TEXT);
            CREATE TABLE nodes (id INTEGER PRIMARY KEY, scan_id TEXT, path TEXT, name TEXT,
                parent_path TEXT, depth INT, is_dir INT, size_self INT, size_total INT,
                file_count INT, dir_count INT, category TEXT, safety TEXT, mtime REAL);
            CREATE TABLE files (id INTEGER PRIMARY KEY, scan_id TEXT, path TEXT, size INT,
                parent_path TEXT, category TEXT, safety TEXT, mtime REAL);
            INSERT INTO scans VALUES ('s', 0, 0, 1, 0, '2026-01-01');
            INSERT INTO nodes VALUES (1,'s','/empty','empty','',0,1,0,0,0,0,'','Safe',0);
        """)
        conn.commit()
        conn.close()
        tree = ScanStore(str(db)).get_tree("s", max_depth=3, top_n=50, max_nodes=8000)
        empty = [n for n in _walk(tree) if n["path"] == "/empty"][0]
        assert empty["_children"] == []


class TestTreemapColours:
    def test_uncategorised_items_are_spread_widely(self):
        # Flat mode is mostly uncategorised folders; a narrow jitter made them
        # one indistinguishable colour.
        paths = ["/var/log", "/var/cache/apt", "/tmp", "/var/tmp", "/var/spool",
                 "/var/lib", "/srv", "/opt", "/usr/share", "/etc"]
        hues = []
        for p in paths:
            col = RequestHandler._compute_color(p, "未分类", 0)
            hues.append(int(col[col.index("(") + 1:col.index(",")]))
        assert max(hues) - min(hues) > 40, f"uncategorised hues collapsed: {hues}"

    def test_named_categories_keep_their_identity(self):
        # A real category must stay recognisable, so its jitter stays narrow.
        base = {"系统日志": 200, "包管理器缓存": 38, "临时文件": 150, "应用缓存": 270}
        for cat, want in base.items():
            for p in ("/a", "/bb", "/ccc", "/dddd", "/eeeee"):
                col = RequestHandler._compute_color(p, cat, 0)
                hue = int(col[col.index("(") + 1:col.index(",")])
                assert abs(hue - want) <= 12, f"{cat} drifted to {hue}"

    def test_other_bucket_stays_grey(self):
        col = RequestHandler._compute_color("/x/__other__", "Other", 0)
        assert col == "hsl(0,0%,55%)"

    def test_depth_still_darkens_without_going_black(self):
        for depth in range(0, 6):
            col = RequestHandler._compute_color("/a/b", "应用缓存", depth)
            light = int(col[col.index(",") + 1:col.index("%")])
            assert light >= 38
