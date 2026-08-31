"""Regression tests for v3.2.2 fixes."""

import json
import sqlite3
import urllib.request
import pytest

from wsl_master.web.server import WslWebServer, RequestHandler
from wsl_master.scan.controller import ScanController

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _api(method, url, data=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Auth-Token"] = token
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    resp = _opener.open(req)
    return resp.status, json.loads(resp.read())


@pytest.fixture
def server(monkeypatch, tmp_path):
    """Server pointed at a fixture DB with a leaf dir containing 3 files."""
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
        INSERT INTO nodes VALUES (1,'scan_test','/data','data','',0,1,100,300,3,1,'','',0);
        INSERT INTO nodes VALUES (2,'scan_test','/data/leaf','leaf','/data',1,1,300,300,3,0,'','',0);
        INSERT INTO files VALUES (1,'scan_test','/data/leaf/a.big',200,'/data/leaf','','Safe',0);
        INSERT INTO files VALUES (2,'scan_test','/data/leaf/b.mid',60,'/data/leaf','系统日志','Safe',0);
        INSERT INTO files VALUES (3,'scan_test','/data/leaf/c.small',40,'/data/leaf','','Safe',0);
        """
    )
    conn.commit()
    conn.close()

    import wsl_master.config as config
    monkeypatch.setattr(config, "DEFAULT_DB_PATH", str(db))
    # server.py imports the name lazily inside handlers, so patching the
    # module attribute is enough.

    controller = ScanController()
    srv = WslWebServer(host="127.0.0.1", port=0)
    port = srv.start(controller)
    token = RequestHandler.auth_token
    yield (f"http://127.0.0.1:{port}", token)
    srv.stop()


class TestLeafDirReturnsAllFiles:
    """_api_tree used to send the response inside the per-file loop,
    so a leaf directory returned exactly ONE file."""

    def test_flat_leaf_dir_lists_all_files(self, server):
        base, token = server
        status, data = _api("GET", f"{base}/api/tree?parent=/data/leaf&depth=0", token=token)
        assert status == 200
        names = sorted(n["name"] for n in data["nodes"])
        assert names == ["a.big", "b.mid", "c.small"]

    def test_flat_leaf_dir_total_is_sum(self, server):
        base, token = server
        _, data = _api("GET", f"{base}/api/tree?parent=/data/leaf&depth=0", token=token)
        assert data["total"] == 300


class TestKeepAliveAndReuse:
    """HTTP/1.1 with Content-Length: responses must carry the header."""

    def test_json_has_content_length(self, server):
        base, token = server
        req = urllib.request.Request(f"{base}/api/health")
        resp = _opener.open(req)
        assert resp.status == 200
        assert int(resp.headers["Content-Length"]) > 0

    def test_static_has_content_length(self, server):
        base, _ = server
        req = urllib.request.Request(f"{base}/")
        resp = _opener.open(req)
        assert resp.status == 200
        assert int(resp.headers["Content-Length"]) > 0


class TestBadJsonBody:
    def test_malformed_post_returns_400_not_500(self, server):
        base, token = server
        req = urllib.request.Request(
            f"{base}/api/scan/start",
            data=b"not json{{{",
            headers={"Content-Type": "application/json", "X-Auth-Token": token},
            method="POST",
        )
        try:
            _opener.open(req)
            assert False, "should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 400


class TestNestedTree:
    def test_nested_tree_returns_children(self, server):
        base, token = server
        _, data = _api("GET", f"{base}/api/tree?parent=/data&depth=2", token=token)
        names = [n["name"] for n in data["nodes"]]
        assert "leaf" in names
        leaf = next(n for n in data["nodes"] if n["name"] == "leaf")
        # nested mode: deep files are folded into the leaf via collect_deep_files
        child_names = sorted(c["name"] for c in leaf.get("children", []))
        assert child_names == ["a.big", "b.mid", "c.small"]


class TestStoreCreatesParentDir:
    def test_fresh_db_dir_is_created_and_empty(self, tmp_path):
        from wsl_master.cache.store import ScanStore
        db = tmp_path / "deep" / "nested" / "cache.db"
        store = ScanStore(str(db))
        # no exception, DB file created with schema
        assert store.list_scans() == []
        assert db.exists()
