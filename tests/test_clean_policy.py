"""清理逻辑测试 —— 安全闸门、计划统计、快速扫描派生、隔离区。

对应需求："不要漏删、也不要错删"：
  * 漏删：全量统计（无 LIMIT 截断）、快速扫描范围由规则派生
  * 错删：白名单/受保护目录/占用中/虚拟环境/权限/规则变更/Caution 全部拦截
"""

import os
import sqlite3
import stat
import sys
import time

import pytest

from wsl_master.clean import policy as policy_mod
from wsl_master.clean.executor import Cleaner
from wsl_master.clean.planner import (
    build_plan, get_plan, select_explicit_paths, select_targets, invalidate_plan_cache,
)
from wsl_master.clean.policy import CleanPolicy, Verdict
from wsl_master.rules.engine import RulesEngine, Rule, quick_scan_roots, rule_root

RULES_YAML = """rules:
  - path: {root}/logs/*.log
    category: "系统日志"
    safety: Safe
    max_depth: 2
    exclude_patterns:
      - {root}/logs/wtmp
  - path: {root}/apps/**
    category: "应用缓存"
    safety: Safe
    max_depth: 4
    exclude_patterns: []
  - path: {root}/caution
    category: "应用缓存"
    safety: Caution
    max_depth: 3
    exclude_patterns: []
whitelist:
  - {root}/logs/keep.log
"""


@pytest.fixture
def junk_tree(tmp_path):
    """A real on-disk tree + rules so the policy can run its filesystem checks."""
    root = tmp_path / "junk"
    for d in ("logs", "caution", "apps/repo/.git", "apps/venv", "apps/adir"):
        (root / d).mkdir(parents=True)
    (root / "apps" / "venv" / "pyvenv.cfg").write_text("home = /usr")
    files = {
        "log": root / "logs" / "app.log",
        "keep": root / "logs" / "keep.log",
        "wtmp": root / "logs" / "wtmp",
        "caution": root / "caution" / "model.bin",
        "repo": root / "apps" / "repo" / ".git" / "config",
        "venv": root / "apps" / "venv" / "lib.py",
        "gone": root / "logs" / "never-existed.log",
    }
    for key in ("log", "keep", "wtmp", "caution", "repo", "venv"):
        files[key].write_text("x" * 10)
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(RULES_YAML.format(root=str(root)), encoding="utf-8")
    return {"root": root, "files": files, "rules": str(rules_file)}


@pytest.fixture(autouse=True)
def _no_recent_guard(monkeypatch):
    """pytest 的 tmp_path 位于 /tmp 下，默认的"10 分钟内仍在写入"守卫会拦下刚创建
    的测试文件；除专门的守卫测试外统一关掉（该测试会自己重新打开）。"""
    monkeypatch.setattr(CleanPolicy, "RECENT_GUARD_ROOTS", ())


@pytest.fixture
def pol(junk_tree, monkeypatch):
    monkeypatch.setattr(policy_mod, "app_protected_paths", lambda: [])
    engine = RulesEngine.from_yaml(junk_tree["rules"])
    return CleanPolicy(junk_tree["rules"], rules_engine=engine)


def _codes(verdict):
    return verdict.code


class TestPolicyGate:
    def test_clean_file_is_deletable(self, pol, junk_tree):
        v = pol.evaluate(str(junk_tree["files"]["log"]), 10,
                         scan_category="系统日志", scan_safety="Safe")
        assert v.deletable and v.code == policy_mod.OK

    def test_whitelist_blocks_even_when_rule_matches(self, pol, junk_tree):
        v = pol.evaluate(str(junk_tree["files"]["keep"]), 10,
                         scan_category="系统日志", scan_safety="Safe")
        assert not v.deletable and v.code == policy_mod.BLOCK_WHITELIST

    def test_excluded_path_is_not_junk_anymore(self, pol, junk_tree):
        # wtmp 被 exclude_patterns 排除 → 已不是垃圾，必须拒绝
        v = pol.evaluate(str(junk_tree["files"]["wtmp"]), 10,
                         scan_category="系统日志", scan_safety="Safe")
        assert not v.deletable and v.code == policy_mod.BLOCK_NO_RULE

    def test_app_protected_dir_blocks(self, junk_tree, monkeypatch):
        # wsl-master 自己的数据库/隔离区/日志目录（运行期解析）永不删除
        monkeypatch.setattr(policy_mod, "app_protected_paths",
                            lambda: [str(junk_tree["root"] / "caution")])
        p = CleanPolicy(junk_tree["rules"],
                        rules_engine=RulesEngine.from_yaml(junk_tree["rules"]))
        v = p.evaluate(str(junk_tree["files"]["caution"]), 10,
                       scan_category="应用缓存", scan_safety="Caution",
                       allow_caution=True)
        assert not v.deletable and v.code == policy_mod.BLOCK_PROTECTED

    def test_caution_requires_explicit_opt_in(self, junk_tree, monkeypatch):
        monkeypatch.setattr(policy_mod, "app_protected_paths", lambda: [])
        engine = RulesEngine.from_yaml(junk_tree["rules"])
        p = CleanPolicy(junk_tree["rules"], rules_engine=engine)
        v = p.evaluate(str(junk_tree["files"]["caution"]), 10,
                       scan_category="应用缓存", scan_safety="Caution")
        assert not v.deletable and v.code == policy_mod.BLOCK_CAUTION
        v2 = p.evaluate(str(junk_tree["files"]["caution"]), 10,
                        scan_category="应用缓存", scan_safety="Caution",
                        allow_caution=True)
        assert v2.deletable

    def test_missing_file_blocked(self, pol, junk_tree):
        v = pol.evaluate(str(junk_tree["files"]["gone"]), 10,
                         scan_category="系统日志", scan_safety="Safe")
        assert not v.deletable and v.code == policy_mod.BLOCK_MISSING

    def test_directory_blocked(self, pol, junk_tree):
        # 扫描时是文件、删除时已变成目录 → 绝不能 rmtree
        v = pol.evaluate(str(junk_tree["root"] / "apps" / "adir"), 0,
                         scan_category="应用缓存", scan_safety="Safe")
        assert not v.deletable and v.code == policy_mod.BLOCK_NOT_FILE

    def test_git_repo_marker_blocks(self, pol, junk_tree):
        v = pol.evaluate(str(junk_tree["files"]["repo"]), 10,
                         scan_category="系统日志", scan_safety="Safe")
        assert not v.deletable and v.code == policy_mod.BLOCK_MARKER

    def test_virtualenv_marker_blocks(self, pol, junk_tree):
        v = pol.evaluate(str(junk_tree["files"]["venv"]), 10,
                         scan_category="系统日志", scan_safety="Safe")
        assert not v.deletable and v.code == policy_mod.BLOCK_MARKER
        assert "虚拟环境" in v.reason

    def test_in_use_blocked(self, pol, junk_tree, monkeypatch):
        target = str(junk_tree["files"]["log"])
        monkeypatch.setattr(policy_mod, "open_paths_snapshot",
                            lambda ttl=2.0: frozenset({target}))
        pol._in_use_at = 0.0
        v = pol.evaluate(target, 10, scan_category="系统日志", scan_safety="Safe")
        assert not v.deletable and v.code == policy_mod.BLOCK_IN_USE

    def test_recent_tempfile_blocked_but_old_one_allowed(self, junk_tree, monkeypatch):
        monkeypatch.setattr(policy_mod, "app_protected_paths", lambda: [])
        root = junk_tree["root"]
        monkeypatch.setattr(CleanPolicy, "RECENT_GUARD_ROOTS", (str(root),))
        engine = RulesEngine.from_yaml(junk_tree["rules"])
        p = CleanPolicy(junk_tree["rules"], rules_engine=engine)

        fresh = root / "logs" / "fresh.log"
        fresh.write_text("x")
        v = p.evaluate(str(fresh), 1, scan_category="系统日志", scan_safety="Safe")
        assert not v.deletable and v.code == policy_mod.BLOCK_RECENT

        old = root / "logs" / "old.log"
        old.write_text("x")
        old_ts = time.time() - 7200
        os.utime(old, (old_ts, old_ts))
        v2 = p.evaluate(str(old), 1, scan_category="系统日志", scan_safety="Safe")
        assert v2.deletable

    def test_symlink_is_deletable(self, junk_tree, monkeypatch):
        monkeypatch.setattr(policy_mod, "app_protected_paths", lambda: [])
        root = junk_tree["root"]
        link = root / "logs" / "link.log"
        link.symlink_to("/etc/hostname")
        p = CleanPolicy(junk_tree["rules"],
                        rules_engine=RulesEngine.from_yaml(junk_tree["rules"]))
        v = p.evaluate(str(link), 0, scan_category="系统日志", scan_safety="Safe")
        assert v.deletable

    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                        reason="root 不受权限位限制")
    def test_unwritable_file_blocked(self, junk_tree, monkeypatch):
        monkeypatch.setattr(policy_mod, "app_protected_paths", lambda: [])
        target = junk_tree["files"]["log"]
        os.chmod(target, 0o400)
        try:
            p = CleanPolicy(junk_tree["rules"],
                            rules_engine=RulesEngine.from_yaml(junk_tree["rules"]))
            v = p.evaluate(str(target), 10, scan_category="系统日志", scan_safety="Safe")
            assert not v.deletable and v.code == policy_mod.BLOCK_PERMISSION
        finally:
            os.chmod(target, 0o600)

    def test_relative_and_traversal_paths_rejected(self, pol):
        assert pol.evaluate("relative/path").code == policy_mod.BLOCK_INVALID
        assert pol.evaluate("/tmp/../etc/passwd").code == policy_mod.BLOCK_INVALID

    def test_verdict_carries_fresh_classification(self, pol, junk_tree):
        v = pol.evaluate(str(junk_tree["files"]["log"]), 10,
                         scan_category="旧的分类", scan_safety="Caution")
        assert v.category == "系统日志" and v.safety == "Safe"


class TestPlanStats:
    @pytest.fixture
    def db(self, tmp_path, junk_tree):
        """files 表里放 700 个真实可删文件 + 若干应被拦截的文件。"""
        conn = sqlite3.connect(str(tmp_path / "scan.db"))
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE files (scan_id TEXT, path TEXT, size INT, parent_path TEXT,
                                category TEXT, safety TEXT, mtime REAL);
            CREATE TABLE scans (scan_id TEXT UNIQUE, total_size INT, total_files INT,
                                total_dirs INT, skipped INT, created_at TEXT DEFAULT (datetime('now')));
        """)
        rows = [("s1", str(junk_tree["files"]["keep"]), 5,
                 str(junk_tree["root"] / "logs"), "系统日志", "Safe", 0)]
        bulk = junk_tree["root"] / "logs"
        for i in range(700):
            f = bulk / ("f%03d.log" % i)
            f.write_text("x" * 10)
            rows.append(("s1", str(f), 10, str(bulk), "系统日志", "Safe", 0))
        rows.append(("s1", str(junk_tree["files"]["caution"]), 999,
                     str(junk_tree["root"] / "caution"), "应用缓存", "Caution", 0))
        conn.executemany("INSERT INTO files VALUES (?,?,?,?,?,?,?)", rows)
        conn.execute("INSERT INTO scans VALUES ('s1', 0, 0, 0, 0, '2026-01-01 00:00:00')")
        conn.commit()
        return conn

    def test_no_truncation_in_stats(self, db, pol):
        invalidate_plan_cache()
        plan = build_plan(db, "s1", pol, per_category_limit=300)
        assert plan.totals["files"] == 702          # 全量统计，不受展示上限影响
        assert plan.totals["safe_files"] == 700
        assert plan.totals["safe_bytes"] == 7000
        assert plan.truncated is True               # 展示被截断
        assert len([f for f in plan.files if f["category"] == "系统日志"]) == 300

    def test_blocked_paths_are_counted_with_reason(self, db, pol):
        invalidate_plan_cache()
        plan = build_plan(db, "s1", pol)
        # 白名单文件被闸门拦下；⚠️ Caution 文件单独计入"需确认"而不是"被拦截"
        assert plan.totals["blocked_files"] == 1
        assert plan.totals["caution_files"] == 1
        codes = {b["code"] for b in plan.blocked_examples}
        assert policy_mod.BLOCK_WHITELIST in codes

    def test_select_targets_honours_category_modes(self, db, pol):
        targets, blocked, rejected, stats = select_targets(
            db, "s1", pol, categories={"系统日志": "safe", "应用缓存": "none"})
        assert len(targets) == 700
        assert stats["files"] == 701          # 白名单文件也在候选里被复核，然后拦下
        assert [b["code"] for b in blocked] == [policy_mod.BLOCK_WHITELIST]
        assert rejected == []

    def test_select_targets_excludes_deselected(self, db, pol, junk_tree):
        drop = [str(f) for f in sorted((junk_tree["root"] / "logs").glob("f*.log"))][:5]
        targets, _blocked, _rejected, _stats = select_targets(
            db, "s1", pol, categories={"系统日志": "safe"}, exclude=drop)
        assert len(targets) == 695
        paths = {t[0] for t in targets}
        assert not (set(drop) & paths)

    def test_select_targets_all_mode_keeps_caution_blocked(self, db, pol):
        monkey_targets, blocked, _rejected, _stats = select_targets(
            db, "s1", pol, categories={"系统日志": "all", "应用缓存": "all"})
        assert len(monkey_targets) == 700
        assert any(b["code"] == policy_mod.BLOCK_CAUTION for b in blocked)

    def test_explicit_paths_mode(self, db, pol, junk_tree):
        good = str(junk_tree["root"] / "logs" / "f000.log")
        targets, blocked, rejected, _stats = select_explicit_paths(
            db, "s1", pol, [good, "/etc/passwd", "/whitelisted"])
        assert [t[0] for t in targets] == [good]
        assert rejected == ["/etc/passwd", "/whitelisted"]

    def test_get_plan_cache_reuses_result(self, db, pol):
        invalidate_plan_cache()
        p1 = get_plan(db, "s1", pol)
        p2 = get_plan(db, "s1", pol)
        assert p1 is p2


class TestQuickScanRoots:
    def test_rule_root_derivation(self):
        assert rule_root("/var/log/*.log") == "/var/log"
        assert rule_root("/tmp/*") == "/tmp"
        assert rule_root("/var/cache/apt/archives/*.deb") == "/var/cache/apt/archives"
        assert rule_root("/var/log/sys*") == "/var/log"
        assert rule_root("/etc/passwd") == "/etc"

    def test_quick_roots_follow_rules(self, tmp_path):
        rules = tmp_path / "r.yaml"
        rules.write_text(
            "rules:\n"
            "  - path: {r}/a/b/*.log\n    category: c\n    safety: Safe\n"
            "  - path: {r}/a\n    category: c\n    safety: Safe\n"
            "  - path: /proc/self/x\n    category: c\n    safety: Safe\n".format(r=tmp_path),
            encoding="utf-8")
        (tmp_path / "a" / "b").mkdir(parents=True)
        roots = quick_scan_roots(str(rules))
        # 嵌套根目录去重（保留最外层），排除目录不参与
        assert roots == [str(tmp_path / "a")]

    def test_quick_roots_default_rules_cover_every_rule_dir(self):
        # 默认规则派生出的根目录必须覆盖仓库里默认规则文件中的目录型规则
        from wsl_master.rules.engine import load_rules_document
        roots = quick_scan_roots()
        assert "/tmp" in roots and any(r.endswith("/.cache") for r in roots)
        assert any(r.endswith("/.npm/_cacache") for r in roots), "npm 缓存必须纳入快速扫描"
        assert any(r.endswith("/.cargo/registry/cache") for r in roots)
        assert load_rules_document(), "默认规则文件必须可加载"


class TestQuarantineSafety:
    def test_same_basename_does_not_overwrite(self, tmp_path):
        cleaner = Cleaner(quarantine_dir=str(tmp_path / "q"), log_dir=str(tmp_path / "l"))
        a = tmp_path / "a"; b = tmp_path / "b"
        a.mkdir(); b.mkdir()
        f1 = a / "same.py"; f2 = b / "same.py"
        f1.write_text("first"); f2.write_text("second")
        report = cleaner.execute([(str(f1), 5, "c", "Safe"), (str(f2), 6, "c", "Safe")],
                                 use_quarantine=True)
        assert report.total_succeeded == 2
        quarantined = cleaner.list_quarantine()
        assert len(quarantined) == 2, "同名文件被覆盖 = 静默数据丢失"
        contents = sorted(open(i["path"]).read() for i in quarantined)
        assert contents == ["first", "second"]
        # 原始路径可以从隔离区精确还原
        assert {i["original_path"] for i in quarantined} == {str(f1), str(f2)}

    def test_restore_by_original_path(self, tmp_path):
        cleaner = Cleaner(quarantine_dir=str(tmp_path / "q"), log_dir=str(tmp_path / "l"))
        f = tmp_path / "data" / "x.log"
        f.parent.mkdir()
        f.write_text("payload")
        cleaner.execute([(str(f), 7, "c", "Safe")], use_quarantine=True)
        assert not f.exists()
        cleaner.restore_from_quarantine(str(f))
        assert f.read_text() == "payload"

    def test_ambiguous_basename_raises_instead_of_guessing(self, tmp_path):
        cleaner = Cleaner(quarantine_dir=str(tmp_path / "q"), log_dir=str(tmp_path / "l"))
        a = tmp_path / "a"; b = tmp_path / "b"
        a.mkdir(); b.mkdir()
        for d in (a, b):
            (d / "dup.py").write_text("x")
        cleaner.execute([(str(a / "dup.py"), 1, "c", "Safe"),
                         (str(b / "dup.py"), 1, "c", "Safe")], use_quarantine=True)
        with pytest.raises(ValueError, match="同名"):
            cleaner.restore_from_quarantine("dup.py")

    def test_manifest_written_for_recovery(self, tmp_path):
        import json
        cleaner = Cleaner(quarantine_dir=str(tmp_path / "q"), log_dir=str(tmp_path / "l"))
        f = tmp_path / "m.log"
        f.write_text("x")
        report = cleaner.execute([(str(f), 1, "c", "Safe")], use_quarantine=True)
        manifest = os.path.join(cleaner.quarantine_dir, report.run_id, "manifest.jsonl")
        entry = json.loads(open(manifest).read().strip())
        assert entry["path"] == str(f) and os.path.exists(entry["quarantine"])

    def test_directory_target_refused_by_default(self, tmp_path):
        cleaner = Cleaner(quarantine_dir=str(tmp_path / "q"), log_dir=str(tmp_path / "l"))
        d = tmp_path / "adir"
        d.mkdir()
        (d / "inner.txt").write_text("x")
        report = cleaner.execute([(str(d), 1, "c", "Safe")], use_quarantine=False)
        assert report.total_failed == 1
        assert d.exists() and (d / "inner.txt").exists(), "扫描后变成目录的路径不得被递归删除"

class TestCleanApi:
    """端到端：/api/clean/preview 与 /api/clean/execute（含安全闸门）。"""

    @pytest.fixture
    def srv(self, tmp_path, junk_tree, monkeypatch):
        import json
        import urllib.request
        import wsl_master.config as cfg
        from wsl_master.web.server import WslWebServer, RequestHandler
        from wsl_master.scan.controller import ScanController

        db = tmp_path / "scan.db"
        conn = sqlite3.connect(str(db))
        conn.executescript("""
            CREATE TABLE files (scan_id TEXT, path TEXT, size INT, parent_path TEXT,
                                category TEXT, safety TEXT, mtime REAL);
            CREATE TABLE scans (scan_id TEXT UNIQUE, total_size INT, total_files INT,
                                total_dirs INT, skipped INT, created_at TEXT DEFAULT (datetime('now')));
        """)
        root = junk_tree["root"]
        rows = [
            ("s1", str(root / "logs" / "app.log"), 10, str(root / "logs"), "系统日志", "Safe", 0),
            ("s1", str(root / "logs" / "keep.log"), 10, str(root / "logs"), "系统日志", "Safe", 0),
            ("s1", str(root / "caution" / "model.bin"), 999, str(root / "caution"), "应用缓存", "Caution", 0),
            ("s1", "/etc/passwd", 10, "/etc", "系统日志", "Safe", 0),
        ]
        conn.executemany("INSERT INTO files VALUES (?,?,?,?,?,?,?)", rows)
        conn.execute("INSERT INTO scans VALUES ('s1', 0, 0, 0, 0, '2026-01-01 00:00:00')")
        conn.commit()
        conn.close()

        monkeypatch.setattr(cfg, "DEFAULT_DB_PATH", str(db))
        monkeypatch.setattr(cfg, "DEFAULT_RULES_PATH", junk_tree["rules"])
        monkeypatch.setattr(cfg, "QUARANTINE_DIR", str(tmp_path / "q"))
        monkeypatch.setattr(cfg, "LOG_DIR", str(tmp_path / "logs"))
        import wsl_master.clean.policy as pol_mod
        monkeypatch.setattr(pol_mod, "app_protected_paths", lambda: [])
        invalidate_plan_cache()

        s = WslWebServer(host="127.0.0.1", port=0)
        port = s.start(ScanController(db_path=str(db), rules_path=junk_tree["rules"]))
        token = RequestHandler.auth_token
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def api(path, data=None):
            req = urllib.request.Request(
                "http://127.0.0.1:%d%s" % (port, path),
                data=json.dumps(data).encode() if data is not None else None,
                headers={"Content-Type": "application/json", "X-Auth-Token": token},
                method="POST" if data is not None else "GET")
            try:
                resp = opener.open(req)
            except urllib.error.HTTPError as exc:   # 4xx 也要能读到 JSON body
                resp = exc
            return json.loads(resp.read())

        yield api, tmp_path, junk_tree
        s.stop()

    def test_preview_counts_everything(self, srv):
        api, _tmp, tree = srv
        d = api("/api/clean/preview")
        assert d["scan_id"] == "s1"
        assert d["totals"]["files"] == 4          # 全量，不再被 LIMIT 500 截断
        # app.log 可删；keep.log 与 /etc/passwd 命中规则但被白名单拦下 → 不在可删集合
        assert d["totals"]["safe_files"] == 1
        assert d["totals"]["safe_bytes"] == 10
        assert d["totals"]["caution_files"] == 1
        blocked = {b["code"] for b in d["blocked_examples"]}
        assert "whitelist" in blocked

    def test_execute_scope_mode_deletes_only_safe(self, srv):
        api, tmp_path, tree = srv
        d = api("/api/clean/preview")
        res = api("/api/clean/execute", {
            "scan_id": d["scan_id"],
            "categories": {"系统日志": "safe", "应用缓存": "none"},
            "quarantine": True,
        })
        assert res["succeeded"] == 1
        assert not (tree["root"] / "logs" / "app.log").exists()
        # ⚠️ 分类未选 + 白名单文件都原样保留
        assert (tree["root"] / "caution" / "model.bin").exists()
        assert (tree["root"] / "logs" / "keep.log").exists()
        assert res["blocked_count"] == 2          # keep.log 与 /etc/passwd 被白名单拦下

    def test_execute_rejects_non_scan_paths(self, srv):
        api, _tmp, _tree = srv
        res = api("/api/clean/execute", {"scan_id": "s1", "paths": ["/etc/shadow"]})
        assert res.get("error")
        assert res.get("rejected") == ["/etc/shadow"]
