"""垃圾清理安全策略 —— 删除前的唯一权威判定。

对应两条硬要求：

* **不要漏删**：扫描结果里所有 category 非空的文件都进入候选集（不再有
  LIMIT 500 这类静默截断），预览与执行走同一套判定；默认勾选集 =
  全部 Safe 且通过安全闸门的文件。
* **不要错删**：每个路径在"显示前"和"删除前"各过一次闸门 ——
  白名单、应用自身数据目录、进程占用、虚拟环境/仓库标记、文件类型、
  写权限、规则变更、Caution 二次确认。任一不通过 → 拦截并给出人话原因，
  绝不静默删除。

本模块只做纯判定（除 /proc 占用快照外不碰数据库），便于单测。
"""

import os
import stat
import threading
import time
from dataclasses import dataclass
from typing import Optional

import wsl_master.config as _config
from wsl_master.rules.engine import PrefixSet, RulesEngine, _is_under, resolve_rules_path

# ── 判定码（前端按码归类展示）──────────────────────────────────────────
OK = "ok"
BLOCK_INVALID = "invalid"          # 非法路径
BLOCK_PROTECTED = "protected"      # 应用自身数据（数据库/回收区/日志/二进制）
BLOCK_WHITELIST = "whitelist"      # 规则文件 whitelist 命中
BLOCK_NO_RULE = "no_rule"          # 已不符合当前清理规则（规则改过/已被排除）
BLOCK_CAUTION = "caution"          # ⚠️ 有代价，需显式确认
BLOCK_MISSING = "missing"          # 文件已不存在（扫描后已被删除/移动）
BLOCK_NOT_FILE = "not_file"        # 目录 / 套接字 / 设备 / FIFO
BLOCK_IN_USE = "in_use"            # 正被进程打开或 mmap
BLOCK_MARKER = "marker"            # 位于虚拟环境 / Git 仓库内
BLOCK_PERMISSION = "permission"    # 无写权限
BLOCK_RECENT = "recent"            # 临时目录中仍在写入

_REASONS = {
    BLOCK_PROTECTED: "受保护：属于 wsl-master 自身数据",
    BLOCK_WHITELIST: "受保护：命中规则白名单",
    BLOCK_CAUTION: "⚠️ 删除有代价，需显式确认",
    BLOCK_MISSING: "文件已不存在（可能已被删除或移动）",
    BLOCK_NOT_FILE: "不是普通文件（目录/套接字/设备），已跳过",
    BLOCK_IN_USE: "正被进程占用，删除可能影响运行中的程序",
    BLOCK_PERMISSION: "无写权限（需要 root）",
    BLOCK_RECENT: "临时目录中 10 分钟内仍在写入",
}


@dataclass(frozen=True)
class Verdict:
    deletable: bool
    code: str = OK
    reason: str = ""
    #: 按"当前规则"复算出的分类与安全级别（可能不同于扫描时的旧值）
    category: str = ""
    safety: str = "Safe"

    def __bool__(self) -> bool:  # 允许 if verdict:
        return self.deletable


# ── 应用自身数据：永不删除 ─────────────────────────────────────────────

def _app_root_of(path: str) -> Optional[str]:
    """往上找到 wsl-master 自己的数据根（/tmp/wsl-master 等）。"""
    cur = os.path.abspath(os.path.expanduser(str(path or "")))
    for _ in range(6):
        base = os.path.basename(cur)
        if base == "wsl-master":
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent
    return None


def app_protected_paths() -> list[str]:
    """运行期计算 —— 数据库/隔离区/日志目录可用环境变量改，不能写死。"""
    out: set = set()
    for p in (_config.DEFAULT_DB_PATH, _config.QUARANTINE_DIR, _config.LOG_DIR):
        if not p:
            continue
        ap = os.path.abspath(os.path.expanduser(str(p)))
        out.add(ap)
        root = _app_root_of(ap)
        if root:
            out.add(root)
    for p in (_config.DEFAULT_RULES_PATH, _config.DEFAULT_SCANNER_PATH):
        if p:
            out.add(os.path.abspath(os.path.expanduser(str(p))))
    return sorted(p for p in out if p and p != os.sep)


# ── 进程占用快照（/proc/*/fd + /proc/*/maps）──────────────────────────

_IN_USE_LOCK = threading.Lock()
_IN_USE_CACHE: dict = {"at": 0.0, "paths": frozenset()}
_IN_USE_TTL = 2.0


def _scan_proc_open_paths() -> set:
    out: set = set()
    try:
        pids = os.listdir("/proc")
    except OSError:
        return out
    for pid in pids:
        if not pid.isdigit():
            continue
        base = "/proc/" + pid
        try:
            fds = os.listdir(base + "/fd")
        except OSError:
            fds = []
        for fd in fds:
            try:
                target = os.readlink(base + "/fd/" + fd)
            except OSError:
                continue
            if target.startswith("/"):
                out.add(target.split(" (deleted)")[0])
        try:
            with open(base + "/maps", "r", errors="replace") as fh:
                for line in fh:
                    parts = line.split(None, 5)
                    if len(parts) == 6 and parts[5].startswith("/"):
                        out.add(parts[5].rstrip().split(" (deleted)")[0])
        except OSError:
            continue
    return out


def open_paths_snapshot(ttl: float = _IN_USE_TTL) -> frozenset:
    """被任何进程打开/映射的文件路径集合（短 TTL 缓存）。"""
    now = time.monotonic()
    with _IN_USE_LOCK:
        if now - _IN_USE_CACHE["at"] < ttl:
            return _IN_USE_CACHE["paths"]
    paths = frozenset(_scan_proc_open_paths())
    with _IN_USE_LOCK:
        _IN_USE_CACHE["at"] = time.monotonic()
        _IN_USE_CACHE["paths"] = paths
    return paths


# ── 策略 ──────────────────────────────────────────────────────────────

class CleanPolicy:
    """删除安全闸门。一次构造，多次 evaluate()。"""

    #: 命中即视为"不是垃圾"的目录标记（虚拟环境 / 代码仓库）
    MARKERS: tuple = (
        ("pyvenv.cfg", "Python 虚拟环境"),
        (".git", "Git 仓库"),
    )
    #: 临时目录中还在写入的文件暂不判为可删
    RECENT_GUARD_SECONDS = 600
    RECENT_GUARD_ROOTS = ("/tmp",)

    def __init__(self, rules_path: Optional[str] = None,
                 rules_engine: Optional[RulesEngine] = None):
        self.rules_path = resolve_rules_path(rules_path)
        if rules_engine is not None:
            self.engine = rules_engine
        elif self.rules_path:
            self.engine = RulesEngine.from_yaml(self.rules_path)
        else:
            self.engine = RulesEngine([])
        self.whitelist = self.engine.whitelist
        self.app_protected = app_protected_paths()
        # trie 化：判定从 O(白名单条数) 降到 O(路径层数)
        self._wl_set = PrefixSet(self.whitelist)
        self._app_set = PrefixSet(self.app_protected)
        self._dir_cache: dict = {}
        self._dir_writable: dict = {}
        self._in_use: frozenset = frozenset()
        self._in_use_at = 0.0
        self._euid = os.geteuid() if hasattr(os, "geteuid") else 0
        try:
            self._groups = set(os.getgroups())
        except OSError:
            self._groups = set()

    # ── 权限判定（不额外 syscall）──────────────────────────────────
    def _mode_writable(self, st: os.stat_result) -> bool:
        if self._euid == 0:
            return True
        if st.st_uid == self._euid:
            return bool(st.st_mode & stat.S_IWUSR)
        if st.st_gid in self._groups:
            return bool(st.st_mode & stat.S_IWGRP)
        return bool(st.st_mode & stat.S_IWOTH)

    def _parent_writable(self, directory: str) -> bool:
        """删除文件需要父目录可写(+x)。按目录缓存，10 万文件只查几千次。"""
        cached = self._dir_writable.get(directory)
        if cached is None:
            cached = os.access(directory, os.W_OK | os.X_OK)
            self._dir_writable[directory] = cached
        return cached

    # ── 内部工具 ──────────────────────────────────────────────────

    def _in_use_paths(self) -> frozenset:
        now = time.monotonic()
        if now - self._in_use_at >= _IN_USE_TTL:
            self._in_use = open_paths_snapshot()
            self._in_use_at = now
        return self._in_use

    def _marker_reason(self, directory: str) -> str:
        """目录（或其任一祖先）内含虚拟环境/仓库标记 → 返回原因。

        按目录缓存：同一个目录下成千上万个文件只走一次祖先链。
        """
        cached = self._dir_cache.get(directory)
        if cached is not None:
            return cached
        chain: list = []
        cur = directory
        reason = ""
        for _ in range(32):
            if cur in self._dir_cache:
                reason = self._dir_cache[cur]
                break
            if not cur or cur == os.sep:
                break
            chain.append(cur)
            for marker, label in self.MARKERS:
                if os.path.exists(os.path.join(cur, marker)):
                    reason = "位于" + label + "内，删除会破坏该环境"
                    break
            if reason:
                break
            cur = os.path.dirname(cur)
        for d in chain:
            self._dir_cache[d] = reason
        return reason

    def _fs_verdict(self, path: str, st: os.stat_result, now: float) -> Verdict:
        if stat.S_ISDIR(st.st_mode):
            return Verdict(False, BLOCK_NOT_FILE, _REASONS[BLOCK_NOT_FILE])
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
            return Verdict(False, BLOCK_NOT_FILE, _REASONS[BLOCK_NOT_FILE])
        if path in self._in_use_paths():
            return Verdict(False, BLOCK_IN_USE, _REASONS[BLOCK_IN_USE])
        parent = os.path.dirname(path) or os.sep
        if not self._parent_writable(parent):
            return Verdict(False, BLOCK_PERMISSION, _REASONS[BLOCK_PERMISSION])
        if stat.S_ISREG(st.st_mode) and not self._mode_writable(st):
            return Verdict(False, BLOCK_PERMISSION, _REASONS[BLOCK_PERMISSION])
        marker = self._marker_reason(parent)
        if marker:
            return Verdict(False, BLOCK_MARKER, marker)
        if now - st.st_mtime < self.RECENT_GUARD_SECONDS:
            if any(part.startswith(".tmp") for part in path.split(os.sep)) or any(
                _is_under(path, root) for root in self.RECENT_GUARD_ROOTS
            ):
                return Verdict(False, BLOCK_RECENT, _REASONS[BLOCK_RECENT])
        return Verdict(True)

    # ── 对外判定 ──────────────────────────────────────────────────

    def evaluate(self, path: str, size: int = 0, *,
                 scan_category: str = "", scan_safety: str = "",
                 allow_caution: bool = False,
                 now: Optional[float] = None) -> Verdict:
        raw = str(path or "")
        if not raw or not raw.startswith(os.sep) or "\u0000" in raw or "/../" in raw:
            return Verdict(False, BLOCK_INVALID, "非法路径")
        p = os.path.normpath(raw)

        if self._app_set.match(p):
            return Verdict(False, BLOCK_PROTECTED, _REASONS[BLOCK_PROTECTED])

        # 规则复核：删的是"现在"的规则，不是扫描那一刻的规则。
        # classify() 内部已含白名单判定（与 Rust 扫描器一致）；只有被判为
        # "无分类"时才需要再区分"白名单"还是"规则已变"（少见，不拖慢主路径）。
        category, safety = self.engine.classify(p, size)
        if not category:
            if self._wl_set.match(p):
                return Verdict(False, BLOCK_WHITELIST, _REASONS[BLOCK_WHITELIST])
            return Verdict(False, BLOCK_NO_RULE,
                           "已不符合当前清理规则（规则已更新或已被排除），请重新扫描")

        if safety == "Caution" and not allow_caution:
            return Verdict(False, BLOCK_CAUTION, _REASONS[BLOCK_CAUTION],
                           category=category, safety=safety)

        try:
            st = os.lstat(p)
        except FileNotFoundError:
            return Verdict(False, BLOCK_MISSING, _REASONS[BLOCK_MISSING],
                           category=category, safety=safety)
        except OSError as exc:
            return Verdict(False, BLOCK_PERMISSION, "无法访问：" + str(exc),
                           category=category, safety=safety)

        verdict = self._fs_verdict(p, st, now if now is not None else time.time())
        return Verdict(verdict.deletable, verdict.code, verdict.reason,
                       category=category, safety=safety)

    def counts_as_junk(self, path: str, size: int = 0) -> bool:
        """是否仍被当前规则判为垃圾（扫描结果与规则的漂移检测）。"""
        category, _ = self.engine.classify(path, size)
        return bool(category)


# ── 进程内共享实例：目录级缓存（占用/标记/权限）跨请求复用 ──────────

_POLICY_LOCK = threading.Lock()
_POLICY_CACHE: dict = {"key": None, "policy": None}


def get_shared_policy(rules_path: Optional[str] = None) -> CleanPolicy:
    """规则文件没变就复用同一个策略实例（缓存热的，冷启动 3s → 0.4s）。"""
    resolved = resolve_rules_path(rules_path)
    try:
        mtime = os.path.getmtime(resolved) if resolved else None
    except OSError:
        mtime = None
    key = (resolved, mtime)
    with _POLICY_LOCK:
        if _POLICY_CACHE["key"] != key:
            _POLICY_CACHE["key"] = key
            _POLICY_CACHE["policy"] = CleanPolicy(resolved)
        return _POLICY_CACHE["policy"]


__all__ = [
    "CleanPolicy", "Verdict", "app_protected_paths", "open_paths_snapshot",
    "get_shared_policy",
    "OK", "BLOCK_INVALID", "BLOCK_PROTECTED", "BLOCK_WHITELIST", "BLOCK_NO_RULE",
    "BLOCK_CAUTION", "BLOCK_MISSING", "BLOCK_NOT_FILE", "BLOCK_IN_USE",
    "BLOCK_MARKER", "BLOCK_PERMISSION", "BLOCK_RECENT",
]
