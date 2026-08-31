#!/usr/bin/env python3
"""WSL Storage Master — CLI entry."""

import argparse
import logging
import logging.handlers
import os
import subprocess
import sys
import threading
from wsl_master import __version__
import webbrowser

from wsl_master.config import DEFAULT_PORT, DEFAULT_HOST, DEFAULT_DB_PATH, DEFAULT_RULES_PATH, LOG_DIR

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.handlers.RotatingFileHandler(
            os.path.join(LOG_DIR, "wsl_master.log"),
            maxBytes=10 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        ),
    ],
)


def _fmt(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size/1024:.1f} KB"
    elif size < 1024**3:
        return f"{size/1024**2:.1f} MB"
    return f"{size/1024**3:.2f} GB"


def cmd_web(args):
    """Start web server and open browser."""
    from wsl_master.web.server import WslWebServer
    from wsl_master.scan.controller import ScanController

    port = args.port
    controller = ScanController()
    server = WslWebServer(host=DEFAULT_HOST, port=port)
    actual_port = server.start(controller)

    url = f"http://{DEFAULT_HOST}:{actual_port}"
    print(f"  WSL Storage Master v{__version__}")
    print(f"  Server: {url}")
    print(f"  Press Ctrl+C to stop")

    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()


def cmd_scan(args):
    """CLI scan mode."""
    from wsl_master.scan.controller import ScanController
    from wsl_master.config import DEFAULT_DB_PATH, DEFAULT_RULES_PATH

    controller = ScanController(
        db_path=getattr(args, 'db', DEFAULT_DB_PATH),
        rules_path=getattr(args, 'rules', DEFAULT_RULES_PATH),
    )
    mode = "quick" if args.quick else "custom"
    paths = args.paths if hasattr(args, 'paths') and args.paths else None

    done_event = threading.Event()
    error_message = []

    def on_progress(data):
        current = data.get("current", "")[:60]
        scanned = data.get("scanned", 0)
        size = data.get("total_bytes", 0)
        print(f"\r  Scanned: {scanned} files | {_fmt(size)} | {current}\033[K", end="", flush=True)

    def on_done(data):
        print()
        sid = data.get("scan_id", "")
        tf = data.get("total_files", data.get("scanned", 0))
        ts = data.get("total_size", data.get("total_bytes", 0))
        if not sid:
            return  # skip progress-layer "done", wait for final
        print(f"\nScan complete!")
        print(f"  Total files: {tf}")
        print(f"  Total size:  {_fmt(ts)}")
        print(f"  Scan ID:     {sid}")
        done_event.set()

    controller.start(mode=mode, paths=paths, on_progress=on_progress, on_done=on_done)

    # Wait with timeout (max 10 minutes)
    if not done_event.wait(timeout=600):
        print("\nScan timed out after 10 minutes")
        controller.stop()


def cmd_list(args):
    """List scan results from cache."""
    from wsl_master.cache.store import ScanStore
    from wsl_master.config import DEFAULT_DB_PATH

    db_path = getattr(args, 'db', DEFAULT_DB_PATH)
    store = ScanStore(db_path)
    scan_id = args.cache or store.get_latest_scan_id()
    if not scan_id:
        print("No scans found. Run 'scan' first.")
        return

    info = store.get_scan_info(scan_id)
    if info:
        print(f"Scan: {scan_id}")
        print(f"  Total size: {_fmt(info['total_size'])}")
        print(f"  Total files: {info['total_files']}")
        print()

    top_n = args.top if hasattr(args, 'top') else 20
    nodes = store.get_nodes(scan_id, top_n=top_n)
    print(f"{'Size':>12} {'Category':<16} {'Path'}")
    print(f"{'-'*12} {'-'*16} {'-'*40}")
    for n in nodes:
        cat = n.get("category", "") or "未分类"
        print(f"{_fmt(n['size_total']):>12} {cat:<16} {n['path'][:60]}")


def cmd_clean(args):
    """Clean files."""
    from wsl_master.cache.store import ScanStore
    from wsl_master.clean.executor import Cleaner
    from wsl_master.config import DEFAULT_DB_PATH

    db_path = getattr(args, 'db', DEFAULT_DB_PATH)
    store = ScanStore(db_path)
    scan_id = store.get_latest_scan_id()
    if not scan_id:
        print("No scans found. Run 'scan' first.")
        return

    cleaner = Cleaner()
    dry_run = args.dry_run

    # Get cleanable files from DB (distinct categories first so the query
    # can seek the category index instead of scanning every file by size)
    conn = store._get_conn()
    from wsl_master.cache.store import distinct_file_categories
    cats = distinct_file_categories(conn, scan_id, db_path)
    if cats:
        placeholders = ",".join("?" * len(cats))
        rows = conn.execute(
            f"SELECT path, size, category, safety FROM files "
            f"WHERE scan_id = ? AND category IN ({placeholders}) "
            f"ORDER BY size DESC LIMIT 100",
            [scan_id] + cats,
        ).fetchall()
    else:
        rows = []
    targets = [(r["path"], r["size"], r["category"], r["safety"]) for r in rows]

    if not targets:
        print("No cleanable files found.")
        return

    if dry_run:
        report = cleaner.dry_run(targets)
        print(report.summary)
        print("\nUse --no-dry-run to actually delete.")
    else:
        confirm = input(f"Delete {len(targets)} files? (yes/NO): ").strip().lower()
        if confirm != "yes":
            print("Cancelled.")
            return
        report = cleaner.execute(targets)
        print(report.summary)


def cmd_vhdx(args):
    """VHDX shrink helper."""
    from wsl_master.vhdx.helper import detect_wsl_instances, generate_shrink_script

    print("Detecting WSL instances...")
    instances = detect_wsl_instances()

    if not instances:
        print("No WSL instances detected.")
        return

    for inst in instances:
        status = "RUNNING" if inst.is_running else "stopped"
        sz = f" ({_fmt(inst.size_bytes)})" if inst.size_bytes else ""
        print(f"  {inst.distro_name} [{status}] {inst.vhdx_path}{sz}")

    paths = [i.vhdx_path for i in instances if i.vhdx_path]
    if paths:
        dst = args.output if hasattr(args, 'output') and args.output else "/mnt/c/Users/Public/compact-wsl-vhdx.ps1"
        generate_shrink_script(paths, dst)
        print(f"\nScript generated: {dst}")
        print("Run in PowerShell (Admin) after wsl --shutdown")


def main():
    parser = argparse.ArgumentParser(description="WSL Storage Master v3")
    parser.add_argument("--port", "-p", type=int, default=DEFAULT_PORT,
                        help=f"Port (default: {DEFAULT_PORT})")
    # Defaults matter: argparse leaves unset options as None, and
    # getattr(args, 'db', fallback) does NOT fall back for a present-but-None
    # attribute — list/clean/scan crashed without an explicit --db/--rules.
    parser.add_argument("--db", default=DEFAULT_DB_PATH,
                        help=f"SQLite database path (env: WSL_MASTER_DB, default: {DEFAULT_DB_PATH})")
    parser.add_argument("--rules", default=DEFAULT_RULES_PATH,
                        help=f"Rules YAML path (env: WSL_MASTER_RULES, default: {DEFAULT_RULES_PATH})")
    sub = parser.add_subparsers(dest="command")

    # web (default)
    p_web = sub.add_parser("web", help="Start web interface")

    # scan
    p_scan = sub.add_parser("scan", help="Run disk scan")
    p_scan.add_argument("paths", nargs="*", help="Paths to scan")
    p_scan.add_argument("--quick", "-q", action="store_true",
                        help="Quick scan (cache/log dirs only)")

    # list
    p_list = sub.add_parser("list", help="List scan results")
    p_list.add_argument("--top", type=int, default=20)
    p_list.add_argument("--cache", help="Use specific scan ID")

    # clean
    p_clean = sub.add_parser("clean", help="Clean files")
    p_clean.add_argument("--no-dry-run", action="store_false", dest="dry_run",
                         default=True, help="Actually delete files (default: dry-run only)")

    # vhdx
    p_vhdx = sub.add_parser("vhdx", help="VHDX shrink helper")
    p_vhdx.add_argument("--output", "-o", help="Output script path")

    args = parser.parse_args()

    if not args.command or args.command == "web":
        cmd_web(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "clean":
        cmd_clean(args)
    elif args.command == "vhdx":
        cmd_vhdx(args)


if __name__ == "__main__":
    main()
