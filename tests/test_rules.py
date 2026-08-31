"""Tests for wsl_master.rules.engine — RulesEngine classification."""

import yaml
import pytest
from wsl_master.rules.engine import RulesEngine, Rule


RULES_YAML = """rules:
  - path: /var/cache/apt/archives/partial
    category: "包管理器缓存"
    safety: Safe
    max_depth: 2
    exclude_patterns: []
  - path: /var/log/*.log
    category: "系统日志"
    safety: Safe
    max_depth: 2
    exclude_patterns:
      - /var/log/wtmp
      - /var/log/btmp
  - path: /tmp/*
    category: "临时文件"
    safety: Safe
    max_depth: 1
    exclude_patterns: []
  - path: ~/.cache/pip
    category: "包管理器缓存"
    safety: Safe
    max_depth: 5
    exclude_patterns: []
  - path: /var/log/*.gz
    category: "系统日志"
    safety: Safe
    max_depth: 2
    exclude_patterns: []
  - path: /etc/test?.conf
    category: "测试规则"
    safety: Caution
    max_depth: 1
    exclude_patterns: []
"""


@pytest.fixture
def engine(tmp_path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(RULES_YAML, encoding="utf-8")
    return RulesEngine.from_yaml(str(rules_file))


def _make_engine(rules: list[Rule]) -> RulesEngine:
    return RulesEngine(rules)


class TestPrefixMatch:
    """Exact and prefix path matching rules (no wildcards)."""

    def test_exact_prefix_match(self, engine):
        cat, safety = engine.classify("/var/cache/apt/archives/partial", 0)
        assert cat == "包管理器缓存"
        assert safety == "Safe"

    def test_prefix_with_subpath(self, engine):
        cat, safety = engine.classify("/var/cache/apt/archives/partial/something", 0)
        assert cat == "包管理器缓存"
        assert safety == "Safe"

    def test_prefix_no_match_different_dir(self, engine):
        cat, safety = engine.classify("/var/cache/apt/other", 0)
        assert cat == ""
        assert safety == "Safe"

    def test_tilde_expansion_prefix(self, engine):
        import os
        path = os.path.expanduser("~/.cache/pip")
        cat, safety = engine.classify(path, 0)
        assert cat == "包管理器缓存"


class TestWildcardMatch:
    """Glob pattern matching via fnmatch.translate regex."""

    def test_star_dot_log_wildcard(self, engine):
        cat, safety = engine.classify("/var/log/auth.log", 0)
        assert cat == "系统日志"
        assert safety == "Safe"

    def test_star_dot_log_no_extension(self, engine):
        cat, safety = engine.classify("/var/log/syslog", 0)
        assert cat == ""
        assert safety == "Safe"

    def test_tmp_star_matches_direct_children(self, engine):
        cat, safety = engine.classify("/tmp/test.txt", 0)
        assert cat == "临时文件"
        assert safety == "Safe"

    def test_question_mark_single_char(self, engine):
        cat, safety = engine.classify("/etc/test1.conf", 0)
        assert cat == "测试规则"
        assert safety == "Caution"

    def test_question_mark_two_chars_no_match(self, engine):
        cat, safety = engine.classify("/etc/test10.conf", 0)
        assert cat == ""
        assert safety == "Safe"

    def test_gz_wildcard(self, engine):
        cat, safety = engine.classify("/var/log/syslog.1.gz", 0)
        assert cat == "系统日志"


class TestExcludePatterns:
    """Exclude patterns override matching rules."""

    def test_wtmp_excluded_from_log_rule(self, engine):
        cat, safety = engine.classify("/var/log/wtmp", 0)
        assert cat == ""
        assert safety == "Safe"

    def test_btmp_excluded_from_log_rule(self, engine):
        cat, safety = engine.classify("/var/log/btmp", 0)
        assert cat == ""
        assert safety == "Safe"

    def test_not_excluded_normal_log(self, engine):
        cat, safety = engine.classify("/var/log/kern.log", 0)
        assert cat == "系统日志"
        assert safety == "Safe"


class TestNoMatch:
    """Paths that match no rules."""

    def test_etc_passwd_no_match(self, engine):
        cat, safety = engine.classify("/etc/passwd", 0)
        assert cat == ""
        assert safety == "Safe"

    def test_empty_path_no_match(self, engine):
        cat, safety = engine.classify("", 0)
        assert cat == ""
        assert safety == "Safe"

    def test_deep_nested_path_no_match(self, engine):
        cat, safety = engine.classify("/var/log/journal/system@abc/system.journal", 0)
        assert cat == ""


class TestMultiRulePriority:
    """First matching rule wins (prefix before pattern)."""

    def test_prefix_wins_over_wildcard(self):
        rules = [
            Rule(path_pattern="/var/log/syslog", category="特定日志", safety="Caution", max_depth=1),
            Rule(path_pattern="/var/log/*.log", category="通用日志", safety="Safe", max_depth=2),
        ]
        engine = _make_engine(rules)
        cat, _ = engine.classify("/var/log/syslog", 0)
        assert cat == "特定日志"

    def test_first_wildcard_wins(self):
        rules = [
            Rule(path_pattern="/var/log/*.log", category="第一规则", safety="Safe", max_depth=2),
            Rule(path_pattern="/var/log/*", category="第二规则", safety="Caution", max_depth=2),
        ]
        engine = _make_engine(rules)
        cat, _ = engine.classify("/var/log/auth.log", 0)
        assert cat == "第一规则"


class TestExcludeCacheKey:
    """Verify _exclude_cache uses path_pattern as key (not id(rule))."""

    def test_cache_key_is_path_pattern(self):
        rules = [
            Rule(path_pattern="/tmp/*", category="临时", safety="Safe", max_depth=1,
                 exclude_patterns=["/tmp/keep-me"]),
        ]
        engine = _make_engine(rules)
        assert "/tmp/*" in engine._exclude_cache
        assert isinstance(engine._exclude_cache["/tmp/*"], list)
        assert len(engine._exclude_cache["/tmp/*"]) == 1

    def test_duplicate_path_patterns_share_cache(self):
        rules = [
            Rule(path_pattern="/tmp/*", category="A", safety="Safe", max_depth=1,
                 exclude_patterns=["/tmp/ex1"]),
            Rule(path_pattern="/tmp/*", category="B", safety="Caution", max_depth=1,
                 exclude_patterns=["/tmp/ex2"]),
        ]
        engine = _make_engine(rules)
        assert "/tmp/*" in engine._exclude_cache
        assert len(engine._exclude_cache) == 1


class TestFromYamlRoundTrip:
    """Ensure from_yaml loads and rules work correctly."""

    def test_rule_count(self, engine):
        assert len(engine.rules) == 6

    def test_prefix_and_pattern_rules_split(self, engine):
        assert len(engine._prefix_rules) == 2  # /var/cache/... and ~/.cache/pip
        assert len(engine._pattern_rules) == 4  # *.log, *.gz, /tmp/*, /etc/test?.conf
