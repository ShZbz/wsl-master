"""WSL Storage Master — Safe deletion and cleanup module.

Supports dry-run, confirmation, quarantine, and deletion logging.

隔离区（quarantine）设计要点
---------------------------
旧实现把每个文件搬到 ``quarantine/<basename>`` 的**扁平目录**里：不同目录下的同名
文件（``__init__.py``、``LICENSE``、``METADATA``…）会互相覆盖，``shutil.move`` 遇到
已存在的目标会静默 rename 覆盖 —— "安全隔离"变成了静默数据丢失，而且事后无法还原。

现在每次执行分配一个 run id，文件按**原始绝对路径**镜像存放：

    <quarantine>/<run_id>/home/u/.cache/uv/archive-v0/xx/pkg/__init__.py

并在 run 目录内实时追加 ``manifest.jsonl``（源路径 → 隔离路径），因此：

* 同名文件永不互相覆盖；
* 进程中途崩溃也能凭 manifest 精确还原；
* ``restore_from_quarantine()`` 无歧义 —— 同名多个时直接拒绝，而不是赌一个。
"""

import os
import shutil
import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

import wsl_master.config as _config

logger = logging.getLogger("wsl_master.cleaner")

MANIFEST_NAME = "manifest.jsonl"


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
    quarantine_path: Optional[str] = None


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
    run_id: str = ""
    quarantine_dir: str = ""

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
        if self.quarantine_dir and self.run_id:
            parts.append(f"  隔离区: {os.path.join(self.quarantine_dir, self.run_id)}")
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

    def __init__(self, quarantine_dir: Optional[str] = None, log_dir: Optional[str] = None):
        # Defaults come from config, which falls back to a user-writable dir
        # when /var/log is root-owned (non-root WSL users would otherwise
        # crash here with PermissionError).
        self.quarantine_dir = quarantine_dir or _config.QUARANTINE_DIR
        self.log_dir = log_dir or _config.LOG_DIR
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def dry_run(self, targets: list) -> DeletionReport:
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

    def execute(self, targets: list, use_quarantine: bool = False,
                allow_dirs: bool = False) -> DeletionReport:
        """Execute deletion or move to quarantine.

        ``allow_dirs`` 默认 False：扫描结果里记录的是文件，若某路径如今变成了目录，
        删除它等于递归删掉整棵子树 —— 这种"扫描后类型变了"的情况一律拒绝。
        """
        report = DeletionReport()
        report.started_at = datetime.now().isoformat()
        report.run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        report.quarantine_dir = self.quarantine_dir if use_quarantine else ""

        for _, _, _, safety in targets:
            if safety == "Safe":
                report.safe_count += 1
            else:
                report.caution_count += 1

        manifest = None
        if use_quarantine:
            run_dir = os.path.join(self.quarantine_dir, report.run_id)
            os.makedirs(run_dir, exist_ok=True)
            manifest = open(os.path.join(run_dir, MANIFEST_NAME), "a", encoding="utf-8")

        try:
            for path, size, category, safety in targets:
                report.total_attempted += 1
                record = DeletionRecord(
                    path=path, size=size, category=category,
                    safety=safety, timestamp=datetime.now().isoformat(),
                    success=False, method="quarantine" if use_quarantine else "delete"
                )
                try:
                    if os.path.isdir(path) and not os.path.islink(path):
                        if not allow_dirs:
                            raise IsADirectoryError(
                                "路径现在是目录，已拒绝删除（避免误删整棵子树）")
                    if use_quarantine:
                        dest = self._move_to_quarantine(path, report.run_id)
                        record.quarantine_path = dest
                        if manifest is not None:
                            manifest.write(json.dumps(
                                {"path": path, "quarantine": dest, "size": size},
                                ensure_ascii=False) + "\n")
                            manifest.flush()
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
        finally:
            if manifest is not None:
                manifest.close()

        report.finished_at = datetime.now().isoformat()
        self._save_log(report)
        return report

    def _delete_path(self, path: str):
        """Delete a file / symlink（目录需显式 allow_dirs，默认走隔离区更安全）"""
        if os.path.islink(path) or os.path.isfile(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=False)
        else:
            raise FileNotFoundError(f"Path not found or unsupported: {path}")

    # ── 隔离区 ────────────────────────────────────────────────────────

    def _quarantine_target(self, path: str, run_id: str) -> str:
        """镜像原始绝对路径 —— 同名文件不再互相覆盖。"""
        rel = os.path.abspath(path).lstrip(os.sep)
        return os.path.join(self.quarantine_dir, run_id, rel)

    def _move_to_quarantine(self, path: str, run_id: str) -> str:
        dest = self._quarantine_target(path, run_id)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        # shutil.move 同时覆盖同盘 rename 与跨盘 copy（此前手写的 copy2 兜底
        # 在目录上会炸 IsADirectoryError）。
        shutil.move(path, dest)
        return dest

    def list_quarantine(self) -> list:
        """List quarantine contents (recursive; original path included)."""
        items = []
        if not os.path.isdir(self.quarantine_dir):
            return items
        for dirpath, _dirnames, filenames in os.walk(self.quarantine_dir):
            for name in filenames:
                if name == MANIFEST_NAME:
                    continue
                full = os.path.join(dirpath, name)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                rel = os.path.relpath(full, self.quarantine_dir)
                run_id = rel.split(os.sep, 1)[0]
                original = os.sep + rel.split(os.sep, 1)[1] if os.sep in rel else name
                items.append({
                    "name": name,
                    "path": full,
                    "original_path": original,
                    "run": run_id,
                    "size": st.st_size,
                    "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                })
        return sorted(items, key=lambda x: x["mtime"], reverse=True)

    def _find_quarantined(self, name: str) -> list:
        """按 basename 或隔离区相对路径查找。"""
        if os.sep in name:
            full = os.path.join(self.quarantine_dir, name.lstrip(os.sep))
            return [full] if os.path.isfile(full) else []
        matches = []
        for item in self.list_quarantine():
            if item["name"] == name:
                matches.append(item["path"])
        return sorted(matches)

    def restore_from_quarantine(self, name: str, dest: Optional[str] = None):
        """Restore a file from quarantine.

        ``name`` 可以是隔离区里的相对路径、原始绝对路径，或唯一的 basename。
        同名多个时**拒绝还原**并报错 —— 赌一个同名文件正是旧实现会把数据搞乱的原因。
        """
        matches = self._find_quarantined(name)
        if not matches and name.startswith(os.sep):
            # 允许直接传原始路径
            rel = name.lstrip(os.sep)
            for item in self.list_quarantine():
                if item["original_path"] == name or item["path"].endswith(os.sep + rel):
                    matches.append(item["path"])
        if not matches:
            raise FileNotFoundError(f"回收区中不存在: {name}")
        if len(matches) > 1:
            raise ValueError(
                f"回收区中有 {len(matches)} 个同名文件，无法确定要还原哪一个；"
                f"请传隔离区相对路径，例如: {os.path.relpath(matches[0], self.quarantine_dir)}")
        src = matches[0]
        if dest is None:
            rel = os.path.relpath(src, self.quarantine_dir)
            dest = os.sep + rel.split(os.sep, 1)[1] if os.sep in rel else os.path.join(
                os.path.expanduser("~"), os.path.basename(src))
        os.makedirs(os.path.dirname(dest) or os.sep, exist_ok=True)
        shutil.move(src, dest)
        logger.info(f"已从回收区恢复: {src} → {dest}")
        return dest

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
                "run_id": report.run_id,
                "quarantine_dir": report.quarantine_dir,
            },
            "records": [asdict(r) for r in report.records],
        }
        with open(log_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"删除日志已保存: {log_path}")
