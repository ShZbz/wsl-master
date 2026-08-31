"""Global configuration constants."""

import os

DEFAULT_PORT = int(os.environ.get("WSL_MASTER_PORT", "8878"))
DEFAULT_HOST = "127.0.0.1"
DEFAULT_DB_PATH = os.environ.get("WSL_MASTER_DB", "/tmp/wsl-master/cache/scan_cache.db")
DEFAULT_RULES_PATH = os.environ.get("WSL_MASTER_RULES", "/opt/wsl-master/config/default_rules.yaml")
DEFAULT_SCANNER_PATH = "/opt/wsl-master/dist/wsl-scanner"

LOG_DIR = "/var/log/wsl-master"
QUARANTINE_DIR = "/tmp/wsl-master/quarantine"
