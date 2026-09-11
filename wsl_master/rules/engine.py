"""规则引擎 — 预编译模式匹配 + 白名单 + 快速扫描根目录派生。

与 Rust 扫描器 (scanner/src/classifier.rs) 保持语义完全一致：

* glob 逐组件匹配（`*` 不跨 `/`，`**` 跨分隔符）
* 前缀规则按路径长度降序（最具体优先），通配符规则按声明顺序
* whitelist 命中的路径既不判为垃圾、也不允许删除
* quick_scan_roots() 由 rules 自动派生快速扫描根目录 —— 规则与扫描范围
  从此只有一个真值来源，不会再出现"规则认识、快速扫描扫不到"的漏删
"""

import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

from wsl_master.config import DEFAULT_RULES_PATH

# 与 scanner/src/main.rs 的 exclude_dirs 保持一致
EXCLUDE_DIRS = ("/proc", "/sys", "/dev", "/run", "/mnt")


def glob_to_regex(pattern: str) -> re.Pattern:
    """Component-wise glob → regex, mirroring scanner/src/classifier.rs.

    Semantics (identical to the Rust scanner so both classifiers agree):
      *  ``*``  matches any run of characters EXCEPT `/` (one component)
      *  ``?``  matches exactly one non-`/` character
      *  ``**`` crosses separators; a trailing ``**/`` segment may also
        match zero directories (``**/x`` matches ``x`` and ``a/b/x``)
      *  ``[...]`` character classes are passed through
    fnmatch was deliberately NOT used: its ``*`` crosses `/`, which made
    the fallback scanner classify nested paths (e.g. ``/var/log/d/x.log``
    under ``/var/log/*.log``) differently from the Rust scanner.
    """
    out = ["^"]
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                if i + 2 < n and pattern[i + 2] == "/":
                    out.append("(?:.*/)?")
                    i += 2
                else:
                    out.append(".*")
                    i += 1
            else:
                out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j != -1:
                out.append(pattern[i:j + 1])
                i = j
            else:
                out.append("\\[")
        elif c in ".+^$(){}|\\":
            out.append("\\" + c)
        else:
            out.append(c)
        i += 1
    out.append("$")
    return re.compile("".join(out))


def _norm(path: str) -> str:
    """Expand ~ and strip trailing separators (keeps '/' intact)."""
    p = os.path.expanduser(str(path or "")).strip()
    if len(p) > 1:
        p = p.rstrip(os.sep)
    return p


def _is_under(path: str, root: str) -> bool:
    """Component-aware containment test ('/tmpfoo' is NOT under '/tmp')."""
    if not root:
        return False
    if root == "/":
        return path.startswith("/")
    return path == root or path.startswith(root + os.sep)


class PrefixSet:
    """前缀集合的 trie 实现 —— 白名单/保护目录判定从 O(条目数) 降到 O(层数)。

    旧实现每个文件都要对 20+ 条白名单做 startswith，10 万文件就是 200 万次
    字符串比较（实测占满一次全量预览 60% 的时间）。
    """

    __slots__ = ("_root",)

    def __init__(self, paths=()):
        self._root: dict = {}
        for p in paths:
            norm = _norm(p)
            if not norm:
                continue
            node = self._root
            for part in norm.strip("/").split("/"):
                node = node.setdefault(part, {})
            node[""] = True          # 终止标记（路径组件不可能为空串）

    def __bool__(self) -> bool:
        return bool(self._root)

    def match(self, path: str) -> bool:
        node = self._root
        if "" in node:               # 收录了 "/"
            return True
        for part in path.strip("/").split("/"):
            node = node.get(part)
            if node is None:
                return False
            if "" in node:           # 命中某个前缀（含等值）
                return True
        return False


@dataclass
class Rule:
    path_pattern: str
    category: str
    safety: str
    max_depth: int
    exclude_patterns: list[str] = field(default_factory=list)
    note: str = ""


def resolve_rules_path(path: Optional[str] = None) -> Optional[str]:
    """Locate the rules file. Explicit path first, then repo-relative
    candidates (the old hardcoded /opt/wsl-master path silently produced an
    empty rule set on any other machine), then the configured default."""
    candidates: list[str] = []
    if path:
        candidates.append(path)
    else:
        candidates.extend([
            os.path.join(os.path.dirname(__file__), "..", "..", "config", "default_rules.yaml"),
            os.path.join(os.getcwd(), "config", "default_rules.yaml"),
            DEFAULT_RULES_PATH,
        ])
    for cand in candidates:
        resolved = os.path.realpath(os.path.expanduser(cand))
        if os.path.exists(resolved):
            return resolved
    return None


def load_rules_document(path: Optional[str] = None) -> dict[str, Any]:
    """Load the raw YAML document (rules + whitelist + excluded_dirs)."""
    resolved = resolve_rules_path(path)
    if not resolved:
        return {}
    with open(resolved, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


class RulesEngine:
    """规则引擎 — 预编译模式匹配，大幅提升 classify() 性能"""

    def __init__(self, rules: list[Rule], whitelist: Optional[list[str]] = None):
        self.rules = rules
        # 预编译：分离前缀规则（快路径）和通配符规则（正则）
        self._prefix_rules: list[tuple[str, Rule]] = []
        self._pattern_rules: list[tuple[re.Pattern, Rule]] = []
        self.whitelist: list[str] = sorted(
            {_norm(w) for w in (whitelist or []) if str(w or "").strip()},
            key=len, reverse=True,
        )

        for rule in rules:
            pattern = os.path.expanduser(rule.path_pattern)
            if any(c in pattern for c in "*?[]"):
                # Component-wise glob (same semantics as the Rust scanner)
                self._pattern_rules.append((glob_to_regex(pattern), rule))
            else:
                # 预拼 "prefix + '/'" —— 每个文件每条规则省一次字符串拼接
                self._prefix_rules.append((pattern, pattern.rstrip(os.sep) + os.sep, rule))

        # 前缀规则按长度降序：最具体的路径优先。
        # Rust 端 classifier.rs 同样排序；此前 Python 保留 YAML 声明顺序，
        # 两套引擎对 "~/.cache" 与 "~/.cache/pip" 这类嵌套前缀规则的判定
        # 可能不一致 —— 扫描器判 Safe、执行端判 Caution 就会造成误删/漏删。
        self._prefix_rules.sort(key=lambda item: len(item[0]), reverse=True)
        self._whitelist_set = PrefixSet(self.whitelist)

        # 排除模式也预编译
        self._exclude_cache: dict[str, list[re.Pattern]] = {}
        for rule in rules:
            if rule.exclude_patterns:
                self._exclude_cache[rule.path_pattern] = [
                    glob_to_regex(os.path.expanduser(exc))
                    for exc in rule.exclude_patterns
                ]

    @classmethod
    def from_default(cls) -> "RulesEngine":
        resolved = resolve_rules_path()
        if resolved:
            return cls.from_yaml(resolved)
        return cls([])

    @classmethod
    def from_yaml(cls, path: str) -> "RulesEngine":
        doc = load_rules_document(path)
        rules = []
        for r in doc.get("rules", []) or []:
            rules.append(Rule(
                path_pattern=r["path"],
                category=r["category"],
                safety=r["safety"],
                max_depth=r.get("max_depth", 0),
                exclude_patterns=r.get("exclude_patterns", []) or [],
                note=r.get("note", ""),
            ))
        return cls(rules, whitelist=doc.get("whitelist", []) or [])

    # ── 白名单 ────────────────────────────────────────────────────────

    def is_whitelisted(self, filepath: str) -> bool:
        """Whitelisted paths are never junk (and never deleted)."""
        expanded = os.path.expanduser(filepath) if "~" in filepath else filepath
        return self._whitelist_set.match(expanded)

    # ── 分类 ──────────────────────────────────────────────────────────

    def classify(self, filepath: str, size: int) -> tuple[str, str]:
        """分类文件 — 先前缀匹配（快），再正则匹配"""
        expanded = os.path.expanduser(filepath) if "~" in filepath else filepath

        if self._whitelist_set.match(expanded):
            return ("", "Safe")

        # 1. 前缀规则（O(1) startswith，无正则开销；最具体优先）
        for prefix, prefix_sep, rule in self._prefix_rules:
            if expanded == prefix or expanded.startswith(prefix_sep):
                if self._is_excluded(expanded, rule):
                    continue
                return (rule.category, rule.safety)

        # 2. 通配符规则（预编译正则，比 fnmatch 快 5-10x）
        for regex, rule in self._pattern_rules:
            if regex.match(expanded):
                if self._is_excluded(expanded, rule):
                    continue
                return (rule.category, rule.safety)

        return ("", "Safe")

    def _is_excluded(self, filepath: str, rule: Rule) -> bool:
        patterns = self._exclude_cache.get(rule.path_pattern)
        if not patterns:
            return False
        for regex in patterns:
            if regex.match(filepath):
                return True
        return False


# ── 快速扫描根目录派生 ───────────────────────────────────────────────

def rule_root(pattern: str) -> str:
    """Derive the scan root a rule needs.

    ``/var/log/*.log`` → ``/var/log``; ``/tmp/*`` → ``/tmp``;
    ``~/.cache/uv`` (prefix rule) → ``~/.cache/uv`` expanded.
    """
    p = os.path.expanduser(str(pattern or ""))
    if not p:
        return ""
    cuts = [p.find(c) for c in "*?[" if p.find(c) != -1]
    cut = min(cuts) if cuts else len(p)
    if cut < len(p):
        head = p[:cut]
        if not head.endswith(os.sep):
            # cut in the middle of a component (/var/log/sys* → /var/log/sys)
            head = head.rsplit(os.sep, 1)[0] + os.sep if os.sep in head else head
        return head.rstrip(os.sep) or os.sep
    # No wildcard: the pattern is a concrete path.
    if os.path.isdir(p):
        return p.rstrip(os.sep) or os.sep
    parent = os.path.dirname(p.rstrip(os.sep))
    return parent.rstrip(os.sep) or os.sep


def _dedup_roots(paths: list[str]) -> list[str]:
    """Keep the topmost roots only — a nested root double-counts every file."""
    unique = sorted(set(paths))
    kept: list[str] = []
    for p in unique:
        if not any(_is_under(p, q) and p != q for q in unique):
            kept.append(p)
    return kept


def quick_scan_roots(rules_path: Optional[str] = None, *, existing_only: bool = True) -> list[str]:
    """快速扫描根目录 = 规则派生 ∪ 兜底目录。

    这是"快速扫描"范围的唯一真值来源：新增一条规则，扫描范围自动跟上，
    不会再出现"规则能识别但快速扫描不覆盖"的漏删。
    """
    doc = load_rules_document(rules_path)
    roots: list[str] = []
    for r in doc.get("rules", []) or []:
        try:
            roots.append(rule_root(r["path"]))
        except (KeyError, TypeError):
            continue
    if not doc:
        # 规则文件缺失时退回内置兜底，避免"快速扫描"变成空扫描
        roots = [
            "/var/cache/apt", "/var/log", "/tmp",
            os.path.expanduser("~/.cache"),
            os.path.expanduser("~/.npm/_cacache"),
            os.path.expanduser("~/.local/share/Trash"),
        ]

    out: list[str] = []
    for root in _dedup_roots([r for r in roots if r]):
        if any(_is_under(root, e) for e in EXCLUDE_DIRS):
            continue
        if existing_only and not os.path.isdir(root):
            continue
        out.append(root)
    return out
