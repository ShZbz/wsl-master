"""Security tests for path traversal and clean API validation."""

import os
import sqlite3
import tempfile
import pytest
from pathlib import Path


class TestPathTraversal:
    """Verify static file serving prevents path traversal."""

    @pytest.fixture
    def static_dir(self):
        """Create a temporary static directory with a known file."""
        with tempfile.TemporaryDirectory() as tmp:
            static = Path(tmp) / "static"
            static.mkdir()
            (static / "index.html").write_text("hello")
            yield static

    def test_absolute_path_bypass_old_fallback(self, static_dir):
        """The old fallback only checks '..', misses absolute paths like /etc/passwd."""
        # Simulate the vulnerable old-fallback logic
        filename = "/etc/passwd"
        filepath = static_dir / filename  # pathlib silently returns absolute path!
        resolved = filepath.resolve()

        # This is what the old fallback checks (vulnerable):
        has_dotdot = ".." in filename
        if has_dotdot:
            blocked = True
        else:
            blocked = False  # BUG: /etc/passwd has no '..' so it passes!

        # /etc/passwd should be blocked but isn't by old fallback
        is_safe = str(resolved).startswith(str(static_dir.resolve()))
        assert not is_safe, (
            "Absolute path resolves outside STATIC_DIR - vulnerability confirmed!"
        )
        assert not blocked, (
            "Old fallback doesn't block '/etc/passwd' because it only checks '..'"
        )

    def test_dotdot_traversal_resolves_outside(self, static_dir):
        """../../../etc/passwd should resolve outside STATIC_DIR."""
        filename = "../../../etc/passwd"
        filepath = (static_dir / filename).resolve()
        is_safe = str(filepath).startswith(str(static_dir.resolve()))
        assert not is_safe, "Path traversal should resolve outside STATIC_DIR"

    def test_normal_file_resolves_inside(self, static_dir):
        """A normal file should stay within STATIC_DIR."""
        filename = "index.html"
        filepath = (static_dir / filename).resolve()
        is_safe = str(filepath).startswith(str(static_dir.resolve()))
        assert is_safe, "Normal file should be within STATIC_DIR"


class TestPathSanitization:
    """Tests for the fixed path sanitization logic using os.path.commonpath."""

    @pytest.fixture
    def static_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            static = Path(tmp) / "static"
            static.mkdir()
            (static / "index.html").write_text("hello")
            yield static

    def _is_safe(self, static_dir, filename):
        """Re-implement the fixed check for testing."""
        raw = static_dir / filename
        filepath = raw.resolve()
        static_resolved = static_dir.resolve()
        return os.path.commonpath([str(filepath), str(static_resolved)]) == str(static_resolved)

    def test_block_absolute_path(self, static_dir):
        """/etc/passwd should be blocked."""
        assert not self._is_safe(static_dir, "/etc/passwd")

    def test_block_dotdot_traversal(self, static_dir):
        """../ should be blocked."""
        assert not self._is_safe(static_dir, "../../../etc/passwd")

    def test_allow_normal_file(self, static_dir):
        """Normal file should be allowed."""
        assert self._is_safe(static_dir, "index.html")

    def test_block_encoded_traversal(self, static_dir):
        """Encoded traversal attempts should be blocked after resolve."""
        # pathlib resolves .. regardless of encoding tricks
        assert not self._is_safe(static_dir, "foo/../../etc/passwd")


class TestCleanApiValidation:
    """Verify /api/clean/execute rejects paths not in scan results."""

    @pytest.fixture
    def scan_db(self, tmp_path):
        """Create a test SQLite DB with scan data mimicking real structure."""
        db = tmp_path / "scan.db"
        conn = sqlite3.connect(str(db))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT UNIQUE, total_size INT, total_files INT,
                total_dirs INT, skipped INT, created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY, scan_id TEXT, path TEXT, size INT,
                parent_path TEXT, category TEXT, safety TEXT, mtime REAL
            );
            INSERT INTO scans VALUES ('scan_test', 10000, 5, 2, 0, '2026-01-01');
            INSERT INTO files VALUES (1, 'scan_test', '/var/log/syslog', 500, '/var/log', '系统日志', 'Safe', 0);
            INSERT INTO files VALUES (2, 'scan_test', '/var/log/auth.log', 300, '/var/log', '系统日志', 'Safe', 0);
            INSERT INTO files VALUES (3, 'scan_test', '/tmp/test.tmp', 200, '/tmp', '临时文件', 'Safe', 0);
            INSERT INTO files VALUES (4, 'scan_test', '/var/cache/apt/pkg.deb', 800, '/var/cache/apt', '包管理器缓存', 'Safe', 0);
            INSERT INTO files VALUES (5, 'scan_test', '/home/user/doc.txt', 100, '/home/user', '', 'Safe', 0);
            INSERT INTO files VALUES (6, 'scan_test', '/var/log/wtmp', 50, '/var/log', '', 'Safe', 0);
        """)
        conn.commit()
        conn.close()
        return db

    def _validate_paths(self, db_path, scan_id, paths):
        """Re-implement the validation logic for testing."""
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        placeholders = ",".join("?" * len(paths))
        rows = conn.execute(
            f"SELECT path, category, safety FROM files WHERE scan_id = ? AND path IN ({placeholders}) AND category != ''",
            [scan_id] + paths,
        ).fetchall()
        conn.close()
        allowed = {r["path"]: (r["category"], r["safety"]) for r in rows}
        rejected = [p for p in paths if p not in allowed]
        return {
            "allowed": [{"path": p, "category": c, "safety": s} for p, (c, s) in allowed.items()],
            "rejected": rejected,
        }

    def test_rejects_path_not_in_scan(self, scan_db):
        """Path not in scan results → rejected."""
        result = self._validate_paths(scan_db, "scan_test", ["/etc/passwd"])
        assert result["rejected"] == ["/etc/passwd"]
        assert result["allowed"] == []

    def test_rejects_uncategorized_path(self, scan_db):
        """Path in scan but no category → rejected."""
        result = self._validate_paths(scan_db, "scan_test", ["/home/user/doc.txt"])
        assert result["rejected"] == ["/home/user/doc.txt"]
        assert result["allowed"] == []

    def test_allows_categorized_path(self, scan_db):
        """Path in scan with category → allowed."""
        result = self._validate_paths(scan_db, "scan_test", ["/var/log/syslog"])
        assert result["rejected"] == []
        assert result["allowed"] == [{"path": "/var/log/syslog", "category": "系统日志", "safety": "Safe"}]

    def test_mixed_paths_partial_rejection(self, scan_db):
        """Mix of valid and invalid paths → partial acceptance."""
        result = self._validate_paths(scan_db, "scan_test", [
            "/var/log/syslog",      # valid
            "/etc/passwd",           # not in scan
            "/home/user/doc.txt",    # in scan but no category
            "/var/cache/apt/pkg.deb",# valid
        ])
        assert "/etc/passwd" in result["rejected"]
        assert "/home/user/doc.txt" in result["rejected"]
        assert len(result["allowed"]) == 2

    def test_rejects_whitelisted_path(self, scan_db):
        """Path in whitelist (like wtmp) even if no category → rejected."""
        result = self._validate_paths(scan_db, "scan_test", ["/var/log/wtmp"])
        assert result["rejected"] == ["/var/log/wtmp"]
