"""WSL Storage Master — Safe deletion and cleanup module.

Supports dry-run, confirmation, quarantine, and deletion logging.
"""

import os
import shutil
import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
from pathlib import Path

logger = logging.getLogger("wsl_master.cleaner")


@dataclass
class DeletionRecord:
    """Single deletion record"""
    path: str
    size: int
    category: str
    safety: str
    timestamp: str
    success: bool
    method: str  # "delete" or "quarantine"
    error: Optional[str] = None


@dataclass
class DeletionReport:
    """Full deletion operation report"""
    total_attempted: int = 0
    total_succeeded: int = 0
    total_failed: int = 0
    total_freed_bytes: int = 0
    safe_count: int = 0
    caution_count: int = 0
    records: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    @property
    def summary(self) -> str:
        """Generate human-readable summary"""
        parts = [
            f"删除报告 ({self.started_at} → {self.finished_at})",
            f"  尝试: {self.total_attempted}",
            f"  成功: {self.total_succeeded}",
            f"  失败: {self.total_failed}",
            f"  释放空间: {_format_size(self.total_freed_bytes)}",
            f"  Safe: {self.safe_count}  Caution: {self.caution_count}",
        ]
        if self.errors:
            parts.append(f"  错误数: {len(self.errors)}")
            for e in self.errors[:5]:
                parts.append(f"    - {e}")
        return "\n".join(parts)


def _format_size(bytes_val: int) -> str:
    """Human-readable size formatting"""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 ** 2:
        return f"{bytes_val / 1024:.1f} KB"
    elif bytes_val < 1024 ** 3:
        return f"{bytes_val / 1024 ** 2:.1f} MB"
    else:
        return f"{bytes_val / 1024 ** 3:.2f} GB"


class Cleaner:
    """Safe deletion executor"""

    def __init__(self, quarantine_dir: Optional[str] = None, log_dir: str = "/var/log/wsl-master"):
        self.quarantine_dir = quarantine_dir or "/tmp/wsl-master/quarantine"
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def dry_run(self, targets: list[tuple[str, int, str, str]]) -> DeletionReport:
        """Simulate deletion, only count — no actual removal"""
        report = DeletionReport()
        report.started_at = datetime.now().isoformat()
        for path, size, category, safety in targets:
            report.total_attempted += 1
            report.total_freed_bytes += size
            if safety == "Safe":
                report.safe_count += 1
            else:
                report.caution_count += 1
            report.records.append(DeletionRecord(
                path=path, size=size, category=category,
                safety=safety, timestamp=datetime.now().isoformat(),
                success=True, method="dry-run"
            ))
        report.finished_at = datetime.now().isoformat()
        report.total_succeeded = report.total_attempted
        return report

    def execute(self, targets: list[tuple[str, int, str, str]],
                use_quarantine: bool = False) -> DeletionReport:
        """Execute deletion or move to quarantine"""
        report = DeletionReport()
        report.started_at = datetime.now().isoformat()

        # Group by safety
        for _, _, _, safety in targets:
            if safety == "Safe":
                report.safe_count += 1
            else:
                report.caution_count += 1

        for path, size, category, safety in targets:
            report.total_attempted += 1
            record = DeletionRecord(
                path=path, size=size, category=category,
                safety=safety, timestamp=datetime.now().isoformat(),
                success=False, method="quarantine" if use_quarantine else "delete"
            )
            try:
                if use_quarantine:
                    self._move_to_quarantine(path)
                else:
                    self._delete_path(path)
                record.success = True
                report.total_succeeded += 1
                report.total_freed_bytes += size
            except Exception as e:
                record.success = False
                record.error = str(e)
                report.total_failed += 1
                report.errors.append(f"{path}: {e}")
                logger.error(f"删除失败 {path}: {e}")

            report.records.append(record)

        report.finished_at = datetime.now().isoformat()
        self._save_log(report)
        return report

    def _delete_path(self, path: str):
        """Delete file or empty directory"""
        if os.path.isfile(path) or os.path.islink(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=False)
        else:
            raise FileNotFoundError(f"Path not found or unsupported: {path}")

    def _move_to_quarantine(self, path: str):
        """Move to quarantine directory (handles cross-filesystem moves)."""
        dest = os.path.join(self.quarantine_dir, os.path.basename(path))
        # Avoid name collisions
        if os.path.exists(dest):
            base, ext = os.path.splitext(os.path.basename(path))
            dest = os.path.join(self.quarantine_dir, f"{base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}")
        try:
            os.rename(path, dest)
        except OSError as e:
            if e.errno == 18:  # EXDEV — cross-device link
                shutil.copy2(path, dest)
                os.remove(path)
            else:
                shutil.move(path, dest)

    def _save_log(self, report: DeletionReport):
        """Save deletion log as JSON"""
        log_path = os.path.join(
            self.log_dir,
            f"deletion_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        data = {
            "summary": {
                "total_attempted": report.total_attempted,
                "total_succeeded": report.total_succeeded,
                "total_failed": report.total_failed,
                "total_freed_bytes": report.total_freed_bytes,
                "safe_count": report.safe_count,
                "caution_count": report.caution_count,
                "started_at": report.started_at,
                "finished_at": report.finished_at,
            },
            "records": [asdict(r) for r in report.records],
        }
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"删除日志已保存: {log_path}")

    def list_quarantine(self) -> list[dict]:
        """List quarantine contents"""
        items = []
        if not os.path.isdir(self.quarantine_dir):
            return items
        for name in os.listdir(self.quarantine_dir):
            full = os.path.join(self.quarantine_dir, name)
            try:
                stat = os.stat(full)
                items.append({
                    "name": name,
                    "path": full,
                    "size": stat.st_size,
                    "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
            except OSError:
                pass
        return sorted(items, key=lambda x: x["mtime"], reverse=True)

    def restore_from_quarantine(self, name: str, dest: Optional[str] = None):
        """Restore file from quarantine"""
        src = os.path.join(self.quarantine_dir, name)
        if not os.path.exists(src):
            raise FileNotFoundError(f"回收区中不存在: {name}")
        dst = dest or os.path.join(os.path.expanduser("~"), name)
        shutil.move(src, dst)
        logger.info(f"已从回收区恢复: {src} → {dst}")
