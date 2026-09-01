"""HTTP server for WSL Master web interface."""

import json
import logging
import os
import secrets
import sys
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from typing import Optional

from wsl_master.config import DEFAULT_HOST, DEFAULT_PORT

logger = logging.getLogger("wsl_master.web")
STATIC_DIR = Path(__file__).parent / "static"


class RequestHandler(BaseHTTPRequestHandler):
    scan_controller = None
    auth_token = None
    rules_engine = None
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def _check_auth(self):
        """Return True if request is authorized, False otherwise."""
        if not self.auth_token:
            return True
        token = self.headers.get("X-Auth-Token") or self.headers.get("x-auth-token")
        if not token:
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            token = query.get("token", [None])[0]
        return token == self.auth_token

    def _reject_unauthorized(self):
        self._send_json({"error": "unauthorized"}, status=401)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self._serve_static("index.html", "text/html; charset=utf-8")
            return
        if path.startswith("/static/"):
            filename = path[len("/static/"):]
            self._serve_static(filename)
            return
        if path == "/api/health":
            self._send_json({"status": "ok"})
            return

        if not self._check_auth():
            self._reject_unauthorized()
            return

        if path == "/api/scan/status":
            self._api_scan_status()
            return
        if path == "/api/scan/list":
            self._api_scan_list()
            return
        if path == "/api/tree":
            self._api_tree(query)
            return
        if path == "/api/tree/files":
            self._api_tree_files(query)
            return
        if path == "/api/clean/preview":
            self._api_clean_preview()
            return
        if path == "/api/vhdx/detect":
            self._api_vhdx_detect()
            return
        if path == "/api/rules/reload":
            self._api_rules_reload()
            return

        self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if not self._check_auth():
            self._reject_unauthorized()
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        body = None
        if length > 0:
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_json({"error": "invalid JSON body"}, status=400)
                return

        if path == "/api/scan/start":
            self._api_scan_start(body)
            return
        if path == "/api/scan/stop":
            self._api_scan_stop()
            return
        if path == "/api/clean/execute":
            self._api_clean_execute(body)
            return
        if path == "/api/vhdx/shrink":
            self._api_vhdx_shrink(body)
            return

        self.send_error(404)

    def _api_scan_start(self, body):
        if not body:
            body = {}
        mode = body.get("mode", "quick")
        paths = body.get("paths")
        self.scan_controller.start(mode=mode, paths=paths)
        self._send_json({"status": "started"})

    def _api_scan_status(self):
        status = self.scan_controller.get_status() if self.scan_controller else {"running": False, "error": "no controller"}
        self._send_json(status)

    def _api_scan_stop(self):
        if self.scan_controller:
            self.scan_controller.stop()
        self._send_json({"status": "stopped"})

    def _api_scan_list(self):
        try:
            from wsl_master.cache.store import ScanStore
            from wsl_master.config import DEFAULT_DB_PATH
            store = ScanStore(DEFAULT_DB_PATH)
            self._send_json({"scans": store.list_scans()})
        except Exception as e:
            logger.error(f"_api_scan_list failed: {e}")
            self._send_json({"scans": [], "error": str(e)}, status=500)

    @staticmethod
    def _hash_str(s: str) -> int:
        h = 0
        for c in s:
            h = ((h << 5) - h) + ord(c)
            h = h & 0xFFFFFFFF
        if h & 0x80000000:
            h = h - 0x100000000
        return h

    @staticmethod
    def _compute_color(item_id: str, category: str, depth: int) -> str:
        bases = {
            "系统日志": (200, 70, 48),
            "包管理器缓存": (38, 78, 48),
            "临时文件": (150, 58, 44),
            "应用缓存": (270, 62, 48),
            "Other": (0, 0, 55),
            "未分类": (180, 50, 48),
        }
        b = bases.get(category)
        if b is None:
            h = (len(item_id) * 37) % 360
            s = 55
            l = 48
        else:
            h, s, l = b
        shift = (RequestHandler._hash_str(item_id) % 24) - 12
        h = (h + shift + 360) % 360
        l = max(38, l - depth * 3)
        return f"hsl({h},{s}%,{l}%)"

    def _node_to_json(self, n: dict) -> dict:
        """Convert db row dict to frontend JSON format recursively."""
        item_id = n["path"]
        category = n.get("category", "") or "未分类"
        depth = n.get("depth", 0)
        result = {
            "id": item_id,
            "parentId": n.get("_display_parent") or n.get("parent_path", ""),
            "name": n["name"],
            "isDir": bool(n.get("is_dir", 0)),
            "size": n.get("size_total", n.get("size_self", 0)),
            "sizeSelf": n.get("size_self", 0),
            "fileCount": n.get("file_count", 0),
            "dirCount": n.get("dir_count", 0),
            "category": category,
            "safety": n.get("safety", "Safe"),
            "depth": depth,
            "color": RequestHandler._compute_color(item_id, category, depth),
        }
        if "_children" in n and n["_children"]:
            result["children"] = [self._node_to_json(c) for c in n["_children"]]
        return result

    @staticmethod
    def _query_int(query, key: str, default: int, lo: int, hi: int) -> int:
        raw = query.get(key, [str(default)])[0]
        try:
            return max(lo, min(int(raw), hi))
        except (ValueError, TypeError):
            return default

    def _api_tree(self, query):
        try:
            from wsl_master.cache.store import ScanStore
            from wsl_master.config import DEFAULT_DB_PATH

            store = ScanStore(DEFAULT_DB_PATH)
            scan_id = query.get("scan_id", [None])[0] or store.get_latest_scan_id()
            parent = query.get("parent", [""])[0] or ""
            top_n = self._query_int(query, "top_n", 50, 1, 500)
            depth_raw = query.get("depth", ["2"])[0]
            try:
                max_depth = max(0, min(int(depth_raw), 5))
            except (ValueError, TypeError):
                max_depth = 2
            try:
                merge_threshold = float(query.get("merge_threshold", ["0.005"])[0])
            except (ValueError, TypeError):
                merge_threshold = 0.005

            if not scan_id:
                self._send_json({"nodes": [], "total": 0, "parent": ""})
                return

            if max_depth <= 1:
                if parent == "":
                    nodes = store.get_nodes(scan_id, parent_path=None, top_n=top_n)
                    if len(nodes) == 1 and nodes[0]["is_dir"]:
                        path = nodes[0]["path"]
                        children = store.get_nodes(scan_id, parent_path=path, top_n=top_n)
                        if len(children) > 1:
                            nodes = children
                            parent = path
                else:
                    nodes = store.get_nodes(scan_id, parent_path=parent, top_n=top_n)
                    if not nodes and parent:
                        import os
                        files = store.get_files(scan_id, parent_path=parent, top_n=top_n)
                        if files:
                            result = []
                            for f in files:
                                fname = os.path.basename(f.get("path", ""))
                                cat = f.get("category", "") or "未分类"
                                result.append({
                                    "id": f["path"], "parentId": f.get("parent_path", parent),
                                    "name": fname, "isDir": False,
                                    "size": f["size"], "sizeSelf": f["size"],
                                    "fileCount": 0, "dirCount": 0,
                                    "category": cat,
                                    "safety": f.get("safety", "Safe"), "depth": 0,
                                    "color": RequestHandler._compute_color(f["path"], cat, 0),
                                })
                            self._send_json({
                                "nodes": result, "total": sum(r["size"] for r in result),
                                "parent": parent or "",
                            })
                            return
                        # Walk up until we find a parent that has children in
                        # the scan. os.path.dirname('/') == '/', so stop when
                        # dirname stops making progress (path not in this scan).
                        walk = parent
                        while walk and not nodes:
                            nxt = os.path.dirname(walk)
                            if nxt == walk:
                                break
                            walk = nxt
                            if walk:
                                nodes = store.get_nodes(scan_id, parent_path=walk, top_n=top_n)
                        if nodes:
                            parent = walk

                total = sum(n["size_total"] for n in nodes)
                threshold_bytes = total * merge_threshold
                keep_dirs = max(top_n, 5)
                result = []
                other_size = 0
                other_count = 0
                dir_count = 0

                for n in nodes:
                    if n["is_dir"]:
                        dir_count += 1
                        if dir_count <= keep_dirs:
                            cat_d = n["category"] or "未分类"
                            d_d = n["depth"]
                            result.append({
                                "id": n["path"], "parentId": n["parent_path"],
                                "name": n["name"], "isDir": True,
                                "size": n["size_total"], "sizeSelf": n["size_self"],
                                "fileCount": n["file_count"], "dirCount": n["dir_count"],
                                "category": cat_d,
                                "safety": n["safety"], "depth": d_d,
                                "color": RequestHandler._compute_color(n["path"], cat_d, d_d),
                            })
                            continue
                    if n["size_total"] >= threshold_bytes:
                        cat_f = n["category"] or "未分类"
                        d_f = n["depth"]
                        result.append({
                            "id": n["path"], "parentId": n["parent_path"],
                            "name": n["name"], "isDir": bool(n["is_dir"]),
                            "size": n["size_total"], "sizeSelf": n["size_self"],
                            "fileCount": n["file_count"], "dirCount": n["dir_count"],
                            "category": cat_f,
                            "safety": n["safety"], "depth": d_f,
                            "color": RequestHandler._compute_color(n["path"], cat_f, d_f),
                        })
                    else:
                        other_size += n["size_total"]
                        other_count += 1

                if other_size > 0:
                    other_id = f"{parent or 'root'}/__other__"
                    other_depth = (nodes[0]["depth"] + 1) if nodes else 0
                    result.append({
                        "id": other_id, "parentId": parent or "",
                        "name": f"Other ({other_count} items)", "isDir": False,
                        "size": other_size, "sizeSelf": other_size,
                        "fileCount": other_count, "dirCount": 0,
                        "category": "Other", "safety": "Safe",
                        "depth": other_depth,
                        "color": RequestHandler._compute_color(other_id, "Other", other_depth),
                    })
            else:
                parent_path = parent if parent else None
                raw_tree = store.get_tree(scan_id, parent_path=parent_path, max_depth=max_depth, top_n=top_n, max_nodes=8000)
                if not raw_tree and parent:
                    import os
                    # Walk up, but stop at '/' — os.path.dirname('/') == '/'
                    # would loop forever when the path isn't in this scan.
                    walk = parent
                    while walk and not raw_tree:
                        nxt = os.path.dirname(walk)
                        if nxt == walk:
                            break
                        walk = nxt
                        if walk:
                            raw_tree = store.get_tree(scan_id, parent_path=walk, max_depth=1, top_n=top_n)
                    if raw_tree:
                        parent = walk
                result = [self._node_to_json(n) for n in raw_tree]
                total = sum(n["size"] for n in result)

            self._send_json({"nodes": result, "total": total, "parent": parent or ""})

        except Exception as e:
            logger.error(f"_api_tree failed: {e}")
            self._send_json({"nodes": [], "total": 0, "parent": "", "error": str(e)}, status=500)

    def _api_tree_files(self, query):
        try:
            from wsl_master.cache.store import ScanStore
            from wsl_master.config import DEFAULT_DB_PATH

            store = ScanStore(DEFAULT_DB_PATH)
            scan_id = query.get("scan_id", [None])[0] or store.get_latest_scan_id()
            parent = query.get("parent", [""])[0]
            top_n = self._query_int(query, "top_n", 200, 1, 2000)

            if not scan_id:
                self._send_json({"files": []})
                return

            files = store.get_files(scan_id, parent_path=parent, top_n=top_n)
            self._send_json({
                "files": [{"path": f["path"], "size": f["size"], "category": f["category"], "safety": f["safety"]} for f in files]
            })
        except Exception as e:
            logger.error(f"_api_tree_files failed: {e}")
            self._send_json({"files": [], "error": str(e)}, status=500)

    def _api_clean_preview(self):
        try:
            from wsl_master.cache.store import ScanStore
            from wsl_master.config import DEFAULT_DB_PATH

            store = ScanStore(DEFAULT_DB_PATH)
            scan_id = store.get_latest_scan_id()
            if not scan_id:
                self._send_json({"files": []})
                return

            # Get all categorized files from DB.
            # `category != ''` alone cannot use the category index, forcing a
            # scan of every file row ordered by size; resolve the distinct
            # categories first (cached per scan) and seek each one instead.
            conn = store._get_conn()
            from wsl_master.cache.store import distinct_file_categories
            cats = distinct_file_categories(conn, scan_id, DEFAULT_DB_PATH)
            if not cats:
                self._send_json({"files": []})
                return
            placeholders = ",".join("?" * len(cats))
            rows = conn.execute(
                f"SELECT path, size, parent_path, category, safety FROM files "
                f"WHERE scan_id = ? AND category IN ({placeholders}) "
                f"ORDER BY size DESC LIMIT 500",
                [scan_id] + cats,
            ).fetchall()
            self._send_json({"files": [dict(r) for r in rows]})
        except Exception as e:
            logger.error(f"_api_clean_preview failed: {e}")
            self._send_json({"files": [], "error": str(e)}, status=500)

    def _api_clean_execute(self, body):
        if not body:
            body = {}
        paths = body.get("paths", [])
        quarantine = body.get("quarantine", True)
        try:
            from wsl_master.cache.store import ScanStore
            from wsl_master.config import DEFAULT_DB_PATH
            from wsl_master.clean.executor import Cleaner

            store = ScanStore(DEFAULT_DB_PATH)
            scan_id = store.get_latest_scan_id()
            if not scan_id:
                self._send_json({"error": "No scan found"}, status=400)
                return

            if not paths:
                self._send_json({"error": "No paths provided"}, status=400)
                return

            # Validate each path: must be in scan results AND have a category
            conn = store._get_conn()
            placeholders = ",".join("?" * len(paths))
            rows = conn.execute(
                f"SELECT path, size, category, safety FROM files "
                f"WHERE scan_id = ? AND path IN ({placeholders}) AND category != ''",
                [scan_id] + paths,
            ).fetchall()
            allowed = {r["path"]: (r["size"], r["category"], r["safety"]) for r in rows}
            rejected = [p for p in paths if p not in allowed]

            if not allowed:
                self._send_json({
                    "error": "No valid paths to clean",
                    "rejected": rejected,
                }, status=400)
                return

            cleaner = Cleaner()
            targets = [(p, s, c, safe) for p, (s, c, safe) in allowed.items()]
            report = cleaner.execute(targets, use_quarantine=quarantine)
            self._send_json({
                "summary": report.summary,
                "succeeded": report.total_succeeded,
                "failed": report.total_failed,
                "rejected": rejected,
            })
        except Exception as e:
            logger.error(f"_api_clean_execute failed: {e}")
            self._send_json({"summary": str(e), "succeeded": 0, "failed": len(paths), "error": str(e)}, status=500)

    def _api_rules_reload(self):
        try:
            from wsl_master.rules.engine import RulesEngine
            RequestHandler.rules_engine = RulesEngine.from_default()
            rule_count = len(RequestHandler.rules_engine.rules)
            self._send_json({"status": "reloaded", "rules": rule_count})
        except Exception as e:
            logger.error(f"_api_rules_reload failed: {e}")
            self._send_json({"error": str(e)}, status=500)

    def _api_vhdx_detect(self):
        try:
            from wsl_master.vhdx.helper import detect_wsl_instances
            instances = detect_wsl_instances()
            self._send_json({
                "instances": [
                    {"distro": i.distro_name, "vhdx_path": i.vhdx_path, "is_running": i.is_running, "size_bytes": i.size_bytes}
                    for i in instances
                ]
            })
        except Exception as e:
            logger.error(f"_api_vhdx_detect failed: {e}")
            self._send_json({"instances": [], "error": str(e)}, status=500)

    def _api_vhdx_shrink(self, body):
        if not body:
            body = {}
        try:
            from wsl_master.vhdx.helper import detect_wsl_instances, generate_shrink_script
            output_path = body.get("output", "/mnt/c/Users/Public/compact-wsl-vhdx.ps1")
            instances = detect_wsl_instances()
            paths = [i.vhdx_path for i in instances if i.vhdx_path]
            if paths:
                generate_shrink_script(paths, output_path)
                self._send_json({"status": "generated", "path": output_path})
            else:
                self._send_json({"error": "no vhdx found", "path": output_path})
        except Exception as e:
            logger.error(f"_api_vhdx_shrink failed: {e}")
            self._send_json({"error": str(e)}, status=500)

    def _serve_static(self, filename: str, content_type: str = None):
        try:
            raw = STATIC_DIR / filename
            filepath = raw.resolve()
            static_resolved = STATIC_DIR.resolve()
            if os.path.commonpath([str(filepath), str(static_resolved)]) != str(static_resolved):
                self.send_error(403)
                return
            if not filepath.exists():
                self.send_error(404)
                return

            if content_type is None:
                ext = filepath.suffix.lower()
                content_type = {
                    ".html": "text/html; charset=utf-8",
                    ".css": "text/css",
                    ".js": "application/javascript",
                    ".json": "application/json",
                    ".png": "image/png",
                    ".svg": "image/svg+xml",
                }.get(ext, "application/octet-stream")

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            data = filepath.read_bytes()
            if filename == "index.html" and self.auth_token:
                data = data.replace(
                    b'<meta name="auth-token" content="">',
                    f'<meta name="auth-token" content="{self.auth_token}">'.encode()
                )
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self.send_error(500)

    def _send_json(self, data, status=200):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class WslWebServer:
    """WSL Master web server."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self._server: Optional[ThreadingHTTPServer] = None

    def start(self, scan_controller) -> int:
        RequestHandler.scan_controller = scan_controller
        RequestHandler.auth_token = secrets.token_urlsafe(16)
        from wsl_master.rules.engine import RulesEngine
        RequestHandler.rules_engine = RulesEngine.from_default()

        class _QuietHTTPServer(ThreadingHTTPServer):
            # Browsers abort status-poll fetches on navigation; without this
            # every aborted connection prints a full BrokenPipe traceback.
            def handle_error(self, request, client_address):
                exc = sys.exc_info()[1]
                if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
                    return
                super().handle_error(request, client_address)

        for attempt in range(10):
            try:
                self._server = _QuietHTTPServer((self.host, self.port), RequestHandler)
                self._server.daemon_threads = True
                self.port = self._server.server_port  # always sync actual port
                break
            except OSError:
                if attempt == 9:
                    raise
                self.port = 0

        self._server.timeout = 1
        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.start()
        return self.port

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if RequestHandler.scan_controller:
            try:
                from wsl_master.cache.store import ScanStore
                from wsl_master.config import DEFAULT_DB_PATH
                store = ScanStore(DEFAULT_DB_PATH)
                store.close()
            except Exception:
                pass
