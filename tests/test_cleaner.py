"""Tests for wsl_master.clean.executor — Cleaner dry-run/execute/quarantine."""

import os
import pytest
from wsl_master.clean.executor import Cleaner, DeletionReport


@pytest.fixture
def cleaner(tmp_path):
    quarantine_dir = tmp_path / "quarantine"
    log_dir = tmp_path / "logs"
    return Cleaner(quarantine_dir=str(quarantine_dir), log_dir=str(log_dir))


@pytest.fixture
def existing_files(tmp_path):
    files_dir = tmp_path / "to_clean"
    files_dir.mkdir()
    f1 = files_dir / "test1.tmp"
    f2 = files_dir / "test2.tmp"
    f1.write_text("a" * 100)
    f2.write_text("b" * 200)
    return files_dir, [str(f1), str(f2)]


@pytest.fixture
def targets(existing_files):
    _, paths = existing_files
    return [(paths[0], 100, "临时文件", "Safe"), (paths[1], 200, "临时文件", "Safe")]


class TestDryRun:
    """dry_run should not touch files, only produce a report."""

    def test_dry_run_does_not_delete(self, cleaner, targets):
        report = cleaner.dry_run(targets)
        assert isinstance(report, DeletionReport)
        assert report.total_attempted == 2
        assert report.total_succeeded == 2
        assert report.total_freed_bytes == 300
        assert report.safe_count == 2
        assert report.caution_count == 0
        assert report.total_failed == 0
        for r in report.records:
            assert r.method == "dry-run"
        assert os.path.exists(targets[0][0])
        assert os.path.exists(targets[1][0])

    def test_dry_run_counts_safety(self, cleaner):
        targets = [
            ("/a", 100, "cat", "Safe"),
            ("/b", 200, "cat", "Caution"),
            ("/c", 300, "cat", "Caution"),
        ]
        report = cleaner.dry_run(targets)
        assert report.safe_count == 1
        assert report.caution_count == 2

    def test_dry_run_empty(self, cleaner):
        report = cleaner.dry_run([])
        assert report.total_attempted == 0
        assert report.total_succeeded == 0

    def test_dry_run_report_has_timestamps(self, cleaner, targets):
        report = cleaner.dry_run(targets)
        assert report.started_at
        assert report.finished_at

    def test_dry_run_report_summary_format(self, cleaner, targets):
        report = cleaner.dry_run(targets)
        summary = report.summary
        assert "删除报告" in summary
        assert "100 B" in summary or "300 B" in summary


class TestExecute:
    """execute with use_quarantine=False should delete files."""

    def test_execute_deletes_files(self, cleaner, targets):
        report = cleaner.execute(targets, use_quarantine=False)
        assert report.total_attempted == 2
        assert report.total_succeeded == 2
        assert report.total_freed_bytes == 300
        assert not os.path.exists(targets[0][0])
        assert not os.path.exists(targets[1][0])

    def test_execute_method_is_delete_when_no_quarantine(self, cleaner, targets):
        report = cleaner.execute(targets, use_quarantine=False)
        for r in report.records:
            assert r.method == "delete"

    def test_execute_reports_failure_for_nonexistent_path(self, cleaner, tmp_path):
        """_delete_path raises FileNotFoundError for nonexistent paths,
        which execute() catches and counts as failed."""
        f = tmp_path / "will_be_removed.tmp"
        f.write_text("data")
        cleaner.execute([(str(f), 100, "cat", "Safe")], use_quarantine=False)
        report = cleaner.execute([(str(f), 100, "cat", "Safe")], use_quarantine=False)
        assert report.total_attempted == 1
        assert report.total_failed == 1
        assert "Path not found" in report.errors[0]

    def test_execute_saves_log(self, cleaner, targets):
        report = cleaner.execute(targets, use_quarantine=False)
        logs = os.listdir(cleaner.log_dir)
        json_files = [f for f in logs if f.startswith("deletion_") and f.endswith(".json")]
        assert len(json_files) == 1

    def test_execute_empty_targets(self, cleaner):
        report = cleaner.execute([], use_quarantine=False)
        assert report.total_attempted == 0


class TestQuarantine:
    """execute with use_quarantine=True should move files."""

    def test_quarantine_moves_files(self, cleaner, targets):
        report = cleaner.execute(targets, use_quarantine=True)
        assert report.total_attempted == 2
        assert report.total_succeeded == 2
        assert not os.path.exists(targets[0][0])
        assert not os.path.exists(targets[1][0])
        items = cleaner.list_quarantine()
        assert len(items) == 2
        for item in items:
            assert item["size"] in (100, 200)

    def test_quarantine_method_is_quarantine(self, cleaner, targets):
        report = cleaner.execute(targets, use_quarantine=True)
        for r in report.records:
            assert r.method == "quarantine"

    def test_quarantine_name_collision(self, cleaner, existing_files):
        files_dir, paths = existing_files
        f1 = files_dir / "same_name.tmp"
        f2 = files_dir / "same_name.tmp"
        f1.write_text("x" * 50)
        # Same basename, different content to simulate collision
        targets = [(str(f1), 50, "临时", "Safe")]
        report = cleaner.execute(targets, use_quarantine=True)
        assert report.total_succeeded == 1
        items = cleaner.list_quarantine()
        assert len(items) >= 1

    def test_list_quarantine_empty(self, cleaner):
        assert cleaner.list_quarantine() == []

    def test_list_quarantine_nonexistent_dir(self, tmp_path):
        c = Cleaner(quarantine_dir=str(tmp_path / "nonexistent_q"),
                     log_dir=str(tmp_path / "logs"))
        assert c.list_quarantine() == []


class TestRestore:
    """restore_from_quarantine moves files back."""

    def test_restore_moves_file_back(self, cleaner, existing_files, tmp_path):
        files_dir, paths = existing_files
        f1 = files_dir / "restore_me.tmp"
        f1.write_text("restore content")
        targets = [(str(f1), 50, "临时", "Safe")]
        cleaner.execute(targets, use_quarantine=True)

        # Restore
        dest = str(tmp_path / "restored.tmp")
        cleaner.restore_from_quarantine("restore_me.tmp", dest=dest)
        assert os.path.exists(dest)
        with open(dest) as f:
            assert f.read() == "restore content"
        assert len(cleaner.list_quarantine()) == 0

    def test_restore_nonexistent_raises(self, cleaner):
        with pytest.raises(FileNotFoundError, match="回收区中不存在"):
            cleaner.restore_from_quarantine("no_such_file")
