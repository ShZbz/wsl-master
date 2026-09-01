"""Global configuration constants."""

import os


def _pick_writable_dir(primary: str, *fallbacks: str) -> str:
    """Return the first candidate dir that exists (or can be created) and is
    writable. /var/log is root-owned on a default WSL install, so a non-root
    user would otherwise crash at import time with PermissionError."""
    for d in (primary, *fallbacks):
        try:
            os.makedirs(d, exist_ok=True)
            probe = os.path.join(d, ".write-probe")
            with open(probe, "w") as f:
                f.write("ok")
            os.remove(probe)
            return d
        except OSError:
            continue
    return "/tmp/wsl-master"  # tmpfs: effectively always writable


DEFAULT_PORT = int(os.environ.get("WSL_MASTER_PORT", "8878"))
DEFAULT_HOST = "127.0.0.1"
DEFAULT_DB_PATH = os.environ.get("WSL_MASTER_DB", "/tmp/wsl-master/cache/scan_cache.db")
DEFAULT_RULES_PATH = os.environ.get("WSL_MASTER_RULES", "/opt/wsl-master/config/default_rules.yaml")
DEFAULT_SCANNER_PATH = "/opt/wsl-master/dist/wsl-scanner"

LOG_DIR = _pick_writable_dir(
    os.environ.get("WSL_MASTER_LOG_DIR", "/var/log/wsl-master"),
    os.path.expanduser("~/.local/state/wsl-master"),
    "/tmp/wsl-master/log",
)
QUARANTINE_DIR = os.environ.get("WSL_MASTER_QUARANTINE", "/tmp/wsl-master/quarantine")
