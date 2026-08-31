"""Tests for wsl_master.cache.store."""

import sqlite3
import pytest
from wsl_master.cache.store import ScanStore


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "test.db"
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
        INSERT INTO scans VALUES ('scan_001', 5000, 10, 3, 0, '2026-01-01');
        INSERT INTO nodes VALUES (1, 'scan_001', '/var', 'var', '', 0, 1, 0, 5000, 10, 3, '', 'Safe', 0);
        INSERT INTO nodes VALUES (2, 'scan_001', '/var/log', 'log', '/var', 1, 1, 0, 3000, 8, 1, '系统日志', 'Safe', 0);
        INSERT INTO nodes VALUES (3, 'scan_001', '/tmp', 'tmp', '', 0, 1, 0, 1000, 2, 0, '临时文件', 'Safe', 0);
        INSERT INTO files VALUES (1, 'scan_001', '/var/log/syslog', 500, '/var/log', '系统日志', 'Safe', 0);
        INSERT INTO files VALUES (2, 'scan_001', '/var/log/auth.log', 300, '/var/log', '系统日志', 'Safe', 0);
    """)
    conn.commit()
    conn.close()
    return ScanStore(str(db))


def test_list_scans(store):
    scans = store.list_scans()
    assert len(scans) == 1
    assert scans[0]["scan_id"] == "scan_001"


def test_get_latest_scan_id(store):
    sid = store.get_latest_scan_id()
    assert sid == "scan_001"


def test_get_nodes_root(store):
    nodes = store.get_nodes("scan_001")
    assert len(nodes) >= 1
    paths = [n["path"] for n in nodes]
    assert "/var" in paths


def test_get_nodes_by_parent(store):
    nodes = store.get_nodes("scan_001", parent_path="/var")
    assert len(nodes) >= 1
    assert nodes[0]["path"] == "/var/log"


def test_get_files(store):
    files = store.get_files("scan_001", "/var/log")
    assert len(files) == 2
    assert files[0]["path"] == "/var/log/syslog"


def test_get_scan_info(store):
    info = store.get_scan_info("scan_001")
    assert info is not None
    assert info["total_size"] == 5000


def test_scan_not_found(store):
    assert store.get_scan_info("nonexistent") is None
