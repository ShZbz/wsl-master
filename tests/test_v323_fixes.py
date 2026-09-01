"""Regression tests for v3.2.3 fixes."""

import json
import os
import sqlite3
import threading
import urllib.request
import pytest

from wsl_master.rules.engine import RulesEngine, Rule, glob_to_regex
from wsl_master.scan.controller import ScanController, _is_excluded

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _api(method, url, data=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Auth-Token"] = token
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    resp = _opener.open(req)
    return resp.status, json.loads(resp.read())


# ── Rules engine: component-wise glob semantics (aligned with Rust) ──


class TestGlobSemantics:
    def test_star_does_not_cross_separator(self):
        # fnmatch's * crossed "/", so the fallback scanner classified nested
        # paths (/var/log/d/x.log under /var/log/*.log) the Rust scanner left
        # uncategorized.
        rules = [Rule(path_pattern="/var/log/*.log", category="系统日志", safety="Safe", max_depth=2)]
        engine = RulesEngine(rules)
        assert engine.classify("/var/log/auth.log", 0)[0] == "系统日志"
        assert engine.classify("/var/log/subdir/x.log", 0)[0] == ""

    def test_doublestar_exclude_matches_nested(self):
        # "**/selfcheck/**" must actually exclude nested selfcheck files.
        rules = [Rule(
            path_pattern="/home/u/.cache/pip",
            category="包管理器缓存", safety="Safe", max_depth=5,
            exclude_patterns=["**/selfcheck/**"],
        )]
        engine = RulesEngine(rules)
        assert engine.classify("/home/u/.cache/pip/wheels/x.whl", 0)[0] == "包管理器缓存"
        assert engine.classify("/home/u/.cache/pip/selfcheck/x.json", 0)[0] == ""

    def test_glob_to_regex_doublestar_forms(self):
        assert glob_to_regex("**/x/**").match("/a/b/x/c")
        assert glob_to_regex("**/x/**").match("x/c")          # "**/" matches zero dirs
        assert glob_to_regex("**/x/**").match("/a/y/c") is None
        assert glob_to_regex("/a/**").match("/a/b/c/d")
        assert glob_to_regex("/a/**").match("/a") is None     # needs something after
        assert glob_to_regex("/a/**").match("/ab/c") is None  # component-aware


# ── Controller: --paths must survive commas ──


class TestBuildArgs:
    def test_paths_with_commas_are_not_joined(self):
        c = ScanController(scanner_path="/x", db_path="/tmp/x.db", rules_path="/x.yaml")
        args = c._build_args("custom", ["/data/a,b", "/data/c"])
        assert args == ["/x", "scan", "--db", "/tmp/x.db", "--rules", "/x.yaml",
                        "--paths", "/data/a,b", "--paths", "/data/c"]

    def test_quick_mode_has_no_paths(self):
        c = ScanController(scanner_path="/x", db_path="/tmp/x.db", rules_path="/x.yaml")
        assert c._build_args("quick", ["/ignored"]) == [
            "/x", "scan", "--db", "/tmp/x.db", "--rules", "/x.yaml", "--quick"]


# ── Excluded roots ──


class TestExcludedRoots:
    def test_is_excluded_component_aware(self):
        assert _is_excluded("/mnt")
        assert _is_excluded("/mnt/c/Users")
        assert not _is_excluded("/tmpfoo")
        assert not _is_excluded("/tmp")


# ── Python fallback scanner: commit + same-second rescan ──


def _force_fallback(monkeypatch):
    """Deterministically force the Python fallback scanner (Popen -> FileNotFoundError)."""
    def _no_scanner(*args, **kwargs):
        raise FileNotFoundError("wsl-scanner not available")
    monkeypatch.setattr("wsl_master.scan.controller.subprocess.Popen", _no_scanner)


class TestPythonFallbackCommits:
    def _run_fallback(self, controller, paths, timeout=30):
        done = threading.Event()

        def on_done(_):
            done.set()

        controller.start(mode="custom", paths=paths, on_done=on_done)
        assert done.wait(timeout), "fallback scan did not finish"

    def test_fallback_data_visible_to_other_connection(self, tmp_path, monkeypatch):
        _force_fallback(monkeypatch)
        root = tmp_path / "data"
        (root / "sub").mkdir(parents=True)
        (root / "f1.bin").write_bytes(b"x" * 100)
        (root / "sub" / "f2.bin").write_bytes(b"y" * 50)

        db = str(tmp_path / "cache" / "scan.db")
        c = ScanController(db_path=db, rules_path="/nonexistent/rules.yaml")
        self._run_fallback(c, [str(root)])

        # A separate connection (what the web server / CLI list uses) must see
        # the scan — previously everything was lost to a rolled-back transaction.
        conn = sqlite3.connect(db)
        scans = conn.execute("SELECT COUNT(*) FROM scans WHERE total_files > 0").fetchone()[0]
        files = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        nodes = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        conn.close()
        assert scans == 1
        assert files == 2
        assert nodes == 2  # root + sub

    def test_same_second_rescan_does_not_integrity_error(self, tmp_path, monkeypatch):
        _force_fallback(monkeypatch)
        root = tmp_path / "data"
        root.mkdir()
        (root / "f.bin").write_bytes(b"x" * 10)

        db = str(tmp_path / "scan.db")
        c = ScanController(db_path=db, rules_path="/nonexistent/rules.yaml")
        self._run_fallback(c, [str(root)])
        sid1 = c.status.scan_id
        self._run_fallback(c, [str(root)])  # same scan_id when within one second
        sid2 = c.status.scan_id

        conn = sqlite3.connect(db)
        rows = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        files = conn.execute(
            "SELECT COUNT(*) FROM files WHERE scan_id = ?", (sid2,)).fetchone()[0]
        latest = conn.execute(
            "SELECT total_files FROM scans WHERE scan_id = ?", (sid2,)).fetchone()[0]
        conn.close()
        # The old bare INSERT raised IntegrityError when both runs shared a
        # scan_id; either way the latest scan must hold consistent data.
        assert rows == (1 if sid1 == sid2 else 2)
        assert files == 1
        assert latest == 1

    def test_fallback_skips_excluded_roots(self, tmp_path, monkeypatch):
        _force_fallback(monkeypatch)
        db = str(tmp_path / "scan.db")
        c = ScanController(db_path=db, rules_path="/nonexistent/rules.yaml")

        def fake_exists(p):
            return True  # pretend /mnt/x exists so only the exclude filter applies

        monkeypatch.setattr("wsl_master.scan.controller.os.path.exists", fake_exists)
        self._run_fallback(c, ["/mnt/x"])

        conn = sqlite3.connect(db)
        scans = conn.execute("SELECT total_files, total_dirs FROM scans").fetchone()
        files = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        nodes = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        conn.close()
        assert scans == (0, 0)
        assert files == 0
        assert nodes == 0

    def test_fallback_can_be_stopped(self, tmp_path, monkeypatch):
        _force_fallback(monkeypatch)
        root = tmp_path / "data"
        root.mkdir()
        for i in range(500):
            (root / f"f{i}.bin").write_bytes(b"x" * 10)

        db = str(tmp_path / "scan.db")
        c = ScanController(db_path=db, rules_path="/nonexistent/rules.yaml")
        c.start(mode="custom", paths=[str(root)])
        c.stop()  # before the walk finishes
        c._thread.join(timeout=10)
        assert not c.status.running
        assert c.get_status()["state"] in ("idle", "done")


# ── Config: log dir fallback for non-root users ──


class TestLogDirFallback:
    def test_pick_writable_dir_skips_unwritable(self, tmp_path):
        from wsl_master.config import _pick_writable_dir
        good = tmp_path / "good"
        picked = _pick_writable_dir("/proc/definitely/not/writable", str(good))
        assert picked == str(good)

    def test_log_dir_is_writable(self):
        import wsl_master.config as config
        probe = os.path.join(config.LOG_DIR, ".probe-test")
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)

    def test_cleaner_default_dirs_come_from_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr("wsl_master.config.LOG_DIR", str(tmp_path / "logs"))
        monkeypatch.setattr("wsl_master.config.QUARANTINE_DIR", str(tmp_path / "quar"))
        from wsl_master.clean.executor import Cleaner
        c = Cleaner()
        assert c.log_dir == str(tmp_path / "logs")
        assert c.quarantine_dir == str(tmp_path / "quar")


# ── Web server: robust query-param parsing ──


@pytest.fixture
def server(monkeypatch, tmp_path):
    from wsl_master.web.server import WslWebServer, RequestHandler

    db = tmp_path / "cache.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT UNIQUE,
            total_size INTEGER DEFAULT 0, total_files INTEGER DEFAULT 0,
            total_dirs INTEGER DEFAULT 0, skipped INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, path TEXT,
            name TEXT, parent_path TEXT DEFAULT '', depth INTEGER DEFAULT 0,
            is_dir INTEGER DEFAULT 0, size_self INTEGER DEFAULT 0, size_total INTEGER DEFAULT 0,
            file_count INTEGER DEFAULT 0, dir_count INTEGER DEFAULT 0,
            category TEXT DEFAULT '', safety TEXT DEFAULT 'Safe', mtime REAL DEFAULT 0);
        CREATE TABLE files (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, path TEXT,
            size INTEGER DEFAULT 0, parent_path TEXT NOT NULL, category TEXT DEFAULT '',
            safety TEXT DEFAULT 'Safe', mtime REAL DEFAULT 0);
        INSERT INTO scans (scan_id) VALUES ('scan_test');
        """
    )
    conn.commit()
    conn.close()

    import wsl_master.config as config
    monkeypatch.setattr(config, "DEFAULT_DB_PATH", str(db))

    controller = ScanController()
    srv = WslWebServer(host="127.0.0.1", port=0)
    port = srv.start(controller)
    token = RequestHandler.auth_token
    yield (f"http://127.0.0.1:{port}", token)
    srv.stop()


class TestTreeParamRobustness:
    def test_bad_top_n_returns_200_not_500(self, server):
        base, token = server
        status, data = _api("GET", f"{base}/api/tree?top_n=abc", token=token)
        assert status == 200
        assert data["nodes"] == []

    def test_bad_merge_threshold_returns_200(self, server):
        base, token = server
        status, data = _api(
            "GET", f"{base}/api/tree?merge_threshold=notafloat&depth=1", token=token)
        assert status == 200

    def test_bad_tree_files_top_n_returns_200(self, server):
        base, token = server
        status, data = _api("GET", f"{base}/api/tree/files?parent=/x&top_n=zzz", token=token)
        assert status == 200
        assert data["files"] == []
