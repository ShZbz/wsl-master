"""清理计划：把扫描结果 + 安全策略折算成"能删什么、能释放多少"。

预览与执行共用同一套代码路径 —— 预览看到的数字就是执行时的实际目标，
不存在"界面显示 500 条、实际删 10 万条"或反过来的情况。
"""

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Optional

from wsl_master.clean.policy import CleanPolicy

#: 每个分类最多回传多少个文件给前端展示（文件多时按大小取前 N 个；
#: 统计数字始终是全量，不受此上限影响）
DISPLAY_PER_CATEGORY = 300

_PLAN_LOCK = threading.Lock()
_PLAN_CACHE: dict = {}
#: 计划缓存时长：连点刷新不重算。删除/换扫描后由 invalidate_plan_cache() 立即失效，
#: 且执行前会重新逐条复核，所以这里的"旧"只影响展示，不影响删除安全性。
_PLAN_TTL = 15.0


@dataclass
class CategoryStat:
    name: str
    files: int = 0                 # 该分类下扫描命中的文件总数
    bytes: int = 0
    safe_files: int = 0            # 判定 Safe 且通过安全闸门（默认勾选）
    safe_bytes: int = 0
    caution_files: int = 0         # ⚠️ 需显式确认后才可删
    caution_bytes: int = 0
    blocked_files: int = 0         # 被安全闸门拦下（占用/虚拟环境/无权限/规则变更…）
    blocked_bytes: int = 0
    blocked: dict = field(default_factory=dict)   # code -> count

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "files": self.files, "bytes": self.bytes,
            "safe_files": self.safe_files, "safe_bytes": self.safe_bytes,
            "caution_files": self.caution_files, "caution_bytes": self.caution_bytes,
            "blocked_files": self.blocked_files, "blocked_bytes": self.blocked_bytes,
            "blocked": dict(self.blocked),
        }


@dataclass
class CleanPlan:
    scan_id: str
    categories: list = field(default_factory=list)
    files: list = field(default_factory=list)
    blocked_examples: list = field(default_factory=list)
    totals: dict = field(default_factory=dict)
    display_limit: int = DISPLAY_PER_CATEGORY
    truncated: bool = False
    generated_at: str = ""
    rules_path: str = ""

    def as_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "categories": [c.as_dict() for c in self.categories],
            "files": self.files,
            "blocked_examples": self.blocked_examples,
            "totals": self.totals,
            "display_limit": self.display_limit,
            "truncated": self.truncated,
            "generated_at": self.generated_at,
            "rules_path": self.rules_path,
        }


def _iter_junk_rows(conn, scan_id: str):
    """扫描命中的全部文件（category 非空），按大小降序。

    这里**不做 LIMIT 截断** —— 旧实现的 LIMIT 500 让 500 名之后的垃圾
    永远删不掉，是"漏删"的头号来源。
    """
    return conn.execute(
        "SELECT path, size, category, safety, mtime FROM files "
        "WHERE scan_id = ? AND category IS NOT NULL AND category != '' "
        "ORDER BY size DESC",
        (scan_id,),
    )


def build_plan(conn, scan_id: str, policy: CleanPolicy, *,
               per_category_limit: int = DISPLAY_PER_CATEGORY) -> CleanPlan:
    """全量统计 + 截断展示。

    统计（safe_bytes / caution_bytes / blocked_*）覆盖**每一个**命中文件；
    只有回传给前端的列表按分类各取前 N 个。

    这里一律按 allow_caution=True 评估 —— 预览要回答的是"哪些能删、能删多少"，
    包括"确认后可以删"的 ⚠️ 文件；真正的删除许可在执行时由
    select_targets(allow_caution=...) 单独把关。
    """
    stats: dict = {}
    display: dict = {}
    blocked_examples: list = []
    per_code_examples: dict = {}
    totals = {"files": 0, "bytes": 0, "safe_files": 0, "safe_bytes": 0,
              "caution_files": 0, "caution_bytes": 0,
              "blocked_files": 0, "blocked_bytes": 0}
    truncated = False

    for row in _iter_junk_rows(conn, scan_id):
        path = row["path"]
        size = row["size"] or 0
        stored_cat = row["category"] or "未分类"
        stored_safety = row["safety"] or "Safe"

        verdict = policy.evaluate(path, size, scan_category=stored_cat,
                                  scan_safety=stored_safety, allow_caution=True)
        # 分类按扫描时的记录分组（保证与执行端 categories 键一致）；
        # 安全级别用"当前规则"复算的结果 —— 规则改过而扫描还是旧的时，
        # 用旧值会把本该默认勾选的文件漏掉。
        cat = stored_cat
        safety = verdict.safety if verdict.category else stored_safety

        stat = stats.get(cat)
        if stat is None:
            stat = stats[cat] = CategoryStat(name=cat)
            display[cat] = []
        stat.files += 1
        stat.bytes += size

        if verdict.deletable:
            if safety == "Safe":
                stat.safe_files += 1
                stat.safe_bytes += size
            else:
                stat.caution_files += 1
                stat.caution_bytes += size
        else:
            stat.blocked_files += 1
            stat.blocked_bytes += size
            stat.blocked[verdict.code] = stat.blocked.get(verdict.code, 0) + 1
            bucket = per_code_examples.setdefault(verdict.code, [])
            if len(bucket) < 3:
                bucket.append({"path": path, "size": size,
                               "category": cat, "reason": verdict.reason,
                               "code": verdict.code})

        bucket = display[cat]
        if len(bucket) < per_category_limit:
            bucket.append({
                "path": path, "size": size, "category": cat,
                "safety": safety, "mtime": row["mtime"] or 0,
                "deletable": verdict.deletable,
                "code": verdict.code, "reason": verdict.reason,
                "selected": bool(verdict.deletable and safety == "Safe"),
            })
        else:
            truncated = True

    for code, items in per_code_examples.items():
        blocked_examples.extend(items)

    for stat in stats.values():
        totals["files"] += stat.files
        totals["bytes"] += stat.bytes
        totals["safe_files"] += stat.safe_files
        totals["safe_bytes"] += stat.safe_bytes
        totals["caution_files"] += stat.caution_files
        totals["caution_bytes"] += stat.caution_bytes
        totals["blocked_files"] += stat.blocked_files
        totals["blocked_bytes"] += stat.blocked_bytes

    files: list = []
    for stat in sorted(stats.values(), key=lambda s: -s.bytes):
        files.extend(display.get(stat.name, []))

    return CleanPlan(
        scan_id=scan_id,
        categories=sorted(stats.values(), key=lambda s: -s.bytes),
        files=files,
        blocked_examples=blocked_examples,
        totals=totals,
        display_limit=per_category_limit,
        truncated=truncated,
        generated_at=datetime.now().isoformat(timespec="seconds"),
        rules_path=policy.rules_path or "",
    )


def get_plan(conn, scan_id: str, policy: CleanPolicy, *,
             use_cache: bool = True) -> CleanPlan:
    """build_plan 的带缓存版本：预览按钮连点/刷新不会反复全表扫描。"""
    key = (scan_id, policy.rules_path)
    now = time.monotonic()
    if use_cache:
        with _PLAN_LOCK:
            hit = _PLAN_CACHE.get(key)
            if hit and now - hit[0] < _PLAN_TTL:
                return hit[1]
    plan = build_plan(conn, scan_id, policy)
    if use_cache:
        with _PLAN_LOCK:
            _PLAN_CACHE[key] = (time.monotonic(), plan)
            if len(_PLAN_CACHE) > 8:
                for k in list(_PLAN_CACHE)[:-8]:
                    _PLAN_CACHE.pop(k, None)
    return plan


def select_targets(conn, scan_id: str, policy: CleanPolicy, *,
                   categories: Optional[dict] = None,
                   include: Iterable = (),
                   exclude: Iterable = (),
                   allow_caution: bool = False):
    """把"用户的选择"翻译成真正的删除目标列表（执行前逐条复核）。

    categories: {分类名: "all" | "safe" | "none"}，None = 全部分类
    include:    额外强制勾选的路径（仍需通过安全闸门）
    exclude:    用户单独取消勾选的路径

    返回 (targets, blocked, rejected, stats)
      targets : [(path, size, category, safety)]
      blocked : [{"path","reason","code"}]  —— 闸门拦下的
      rejected: include 里不在本次扫描/已非垃圾的路径
    """
    include_set = {str(p) for p in (include or ()) if p}
    exclude_set = {str(p) for p in (exclude or ()) if p}
    modes = None
    if categories is not None:
        modes = {k: v for k, v in categories.items() if v in ("all", "safe")}

    if modes is not None and not modes:
        rows = []
    elif modes is None:
        rows = _iter_junk_rows(conn, scan_id)
    else:
        placeholders = ",".join("?" * len(modes))
        rows = conn.execute(
            "SELECT path, size, category, safety, mtime FROM files "
            "WHERE scan_id = ? AND category IS NOT NULL AND category != '' "
            "AND category IN (" + placeholders + ") ORDER BY size DESC",
            [scan_id] + list(modes),
        )

    targets: list = []
    blocked: list = []
    seen: set = set()
    stats = {"files": 0, "bytes": 0, "blocked": 0}

    for row in rows:
        path = row["path"]
        size = row["size"] or 0
        stored_cat = row["category"] or "未分类"
        stored_safety = row["safety"] or "Safe"
        if path in exclude_set:
            continue
        forced = path in include_set

        verdict = policy.evaluate(path, size, scan_category=stored_cat,
                                  scan_safety=stored_safety, allow_caution=allow_caution)
        # 分组/勾选一律按扫描记录的分类（与预览返回的 categories 键一致），
        # 判定结果用当前规则复算出的安全级别
        cat = stored_cat
        safety = verdict.safety if verdict.category else stored_safety

        if not forced:
            mode = "all" if modes is None else modes.get(cat, "none")
            if mode == "none":
                continue
            if mode == "safe" and safety != "Safe":
                continue
        seen.add(path)
        stats["files"] += 1
        stats["bytes"] += size

        if not verdict.deletable:
            stats["blocked"] += 1
            blocked.append({"path": path, "size": size, "category": cat,
                            "code": verdict.code, "reason": verdict.reason})
            continue
        targets.append((path, size, cat, safety))

    rejected = sorted(p for p in include_set if p not in seen)
    return targets, blocked, rejected, stats


def select_explicit_paths(conn, scan_id: str, policy: CleanPolicy,
                          paths: Iterable, *, allow_caution: bool = False):
    """老接口兼容：按显式路径列表删除（仍逐条过安全闸门）。

    返回 (targets, blocked, rejected, stats)
    """
    wanted = {str(p) for p in (paths or ()) if p}
    targets: list = []
    blocked: list = []
    seen: set = set()
    stats = {"files": 0, "bytes": 0, "blocked": 0}
    if wanted:
        placeholders = ",".join("?" * len(wanted))
        rows = conn.execute(
            "SELECT path, size, category, safety FROM files "
            "WHERE scan_id = ? AND category IS NOT NULL AND category != '' "
            "AND path IN (" + placeholders + ")",
            [scan_id] + sorted(wanted),
        )
        for row in rows:
            path = row["path"]
            size = row["size"] or 0
            seen.add(path)
            stats["files"] += 1
            stats["bytes"] += size
            verdict = policy.evaluate(path, size, scan_category=row["category"],
                                      scan_safety=row["safety"],
                                      allow_caution=allow_caution)
            if not verdict.deletable:
                stats["blocked"] += 1
                blocked.append({"path": path, "size": size,
                                "category": verdict.category or row["category"],
                                "code": verdict.code, "reason": verdict.reason})
                continue
            targets.append((path, size, verdict.category or row["category"],
                            verdict.safety))
    rejected = sorted(wanted - seen)
    return targets, blocked, rejected, stats


def invalidate_plan_cache() -> None:
    with _PLAN_LOCK:
        _PLAN_CACHE.clear()
