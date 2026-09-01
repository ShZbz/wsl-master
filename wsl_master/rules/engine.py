import os
import re
import yaml
from dataclasses import dataclass, field


def glob_to_regex(pattern: str) -> re.Pattern:
    """Component-wise glob → regex, mirroring scanner/src/classifier.rs.

    Semantics (identical to the Rust scanner so both classifiers agree):
      *  ``*``  matches any run of characters EXCEPT ``/`` (one component)
      *  ``?``  matches exactly one non-``/`` character
      *  ``**`` crosses separators; a trailing ``**/`` segment may also
        match zero directories (``**/x`` matches ``x`` and ``a/b/x``)
      *  ``[...]`` character classes are passed through
    fnmatch was deliberately NOT used: its ``*`` crosses ``/``, which made
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


@dataclass
class Rule:
    path_pattern: str
    category: str
    safety: str
    max_depth: int
    exclude_patterns: list[str] = field(default_factory=list)


class RulesEngine:
    """规则引擎 — 预编译模式匹配，大幅提升 classify() 性能"""

    def __init__(self, rules: list[Rule]):
        self.rules = rules
        # 预编译：分离前缀规则（快路径）和通配符规则（正则）
        self._prefix_rules: list[tuple[str, Rule]] = []
        self._pattern_rules: list[tuple[re.Pattern, Rule]] = []

        for rule in rules:
            pattern = os.path.expanduser(rule.path_pattern)
            if any(c in pattern for c in "*?[]"):
                # Component-wise glob (same semantics as the Rust scanner)
                self._pattern_rules.append((glob_to_regex(pattern), rule))
            else:
                self._prefix_rules.append((pattern, rule))

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
        candidates = [
            "/opt/wsl-master/config/default_rules.yaml",
            os.path.join(os.path.dirname(__file__), "..", "config", "default_rules.yaml"),
        ]
        for path in candidates:
            resolved = os.path.realpath(path)
            if os.path.exists(resolved):
                return cls.from_yaml(resolved)
        return cls([])

    @classmethod
    def from_yaml(cls, path: str) -> "RulesEngine":
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        rules = []
        for r in data.get("rules", []):
            rules.append(Rule(
                path_pattern=r["path"],
                category=r["category"],
                safety=r["safety"],
                max_depth=r["max_depth"],
                exclude_patterns=r.get("exclude_patterns", []),
            ))
        return cls(rules)

    def classify(self, filepath: str, size: int) -> tuple[str, str]:
        """分类文件 — 先前缀匹配（快），再正则匹配"""
        expanded = os.path.expanduser(filepath)

        # 1. 前缀规则（O(1) startswith，无正则开销）
        for prefix, rule in self._prefix_rules:
            if expanded == prefix or expanded.startswith(prefix + os.sep):
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
