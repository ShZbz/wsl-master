"""WSL Storage Master — VHDX Shrink Helper

Auto-detect WSL VHDX locations and generate PowerShell compaction scripts.
"""

import os
import re
import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


@dataclass
class VhdxInfo:
    """WSL VHDX info"""
    distro_name: str
    vhdx_path: str
    is_running: bool
    size_bytes: Optional[int] = None


def detect_wsl_instances() -> list[VhdxInfo]:
    """Detect all WSL distro VHDX paths"""
    instances = []
    try:
        result = subprocess.run(
            ["wsl.exe", "-l", "-v"],
            capture_output=True, timeout=15
        )
        # wsl.exe outputs UTF-16 LE on Windows
        # Format: "  NAME            STATE           VERSION"
        #         "* Ubuntu-24.04    Running         2"
        stdout = result.stdout.decode("utf-16-le", errors="replace")
        _RE = re.compile(r'^\s*(?:\*)?\s*(.+?)\s{2,}(Running|Stopped)\s+(\d+)')
        for line in stdout.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            m = _RE.match(line)
            if not m:
                continue
            distro = m.group(1).strip()
            is_running = m.group(2) == "Running"

            info = VhdxInfo(
                distro_name=distro,
                vhdx_path=_find_vhdx_path(distro),
                is_running=is_running,
            )
            if info.vhdx_path:
                try:
                    info.size_bytes = os.path.getsize(info.vhdx_path)
                except OSError:
                    pass
                instances.append(info)
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        pass
    return instances


def _find_vhdx_path(distro: str) -> Optional[str]:
    """Probe common VHDX path patterns"""
    # Detect Windows username
    try:
        whoami = subprocess.run(
            ["cmd.exe", "/c", "echo", "%USERNAME%"],
            capture_output=True, timeout=5,
            encoding="utf-8", errors="replace"
        ).stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        whoami = None

    if not whoami:
        return None

    base = f"/mnt/c/Users/{whoami}/AppData/Local/Packages"

    # Standard WSL paths
    if distro.lower() == "docker-desktop":
        # Glob from the Packages base — the old code globbed from inside
        # .../DockerDesktop/local-cache, so the pattern could never match.
        matches = sorted(Path(base).glob("DockerDesktop*/local-cache/ext4.vhdx"))
        if matches:
            return str(matches[0])
    elif distro.lower() == "docker-desktop-data":
        matches = sorted(Path(base).glob("DockerDesktop*/local-cache/*ext4*.vhdx"))
        if matches:
            return str(matches[0])

    # WSL2 official package naming: TheDebianProject.DebianGNULinux_xxx, etc.
    # Use iterdir to find matching package directory (fast on WSL 9p)
    distro_lower = distro.lower().replace("-", "").replace(".", "").replace(" ", "")
    for d in Path(base).iterdir():
        if not d.is_dir():
            continue
        dname = d.name.lower().replace("-", "").replace(".", "").replace(" ", "")
        if distro_lower in dname or dname in distro_lower:
            for vhdx_name in ("ext4.vhdx", "disc.vhdx"):
                vhdx = d / "LocalState" / vhdx_name
                if vhdx.exists():
                    return str(vhdx)

    # Limited-depth search (VHDX always under PackageName/LocalState/)
    # Use iterdir, not rglob, since recursive glob is slow on WSL 9p
    all_vhdx = []
    for d in Path(base).iterdir():
        if not d.is_dir():
            continue
        vhdx = d / "LocalState" / "ext4.vhdx"
        if vhdx.exists():
            all_vhdx.append(vhdx)
        disc = d / "LocalState" / "disc.vhdx"
        if disc.exists():
            all_vhdx.append(disc)
    for v in all_vhdx:
        if distro.lower() in str(v).lower():
            return str(v)

    return None


def generate_shrink_script(vhdx_paths: list[str], output_path: str) -> str:
    """Generate PowerShell compaction script with export backup hint"""
    lines = [
        "# WSL Storage Master — VHDX Compaction Script",
        "# Run in Windows PowerShell (Admin)",
        "# Before running: wsl --shutdown",
        "",
        "# TIP: Before compaction, consider backing up your VHDX:",
        "#   wsl --export <distro> C:\\Backup\\<distro>.tar",
        "# This creates a full backup that can be re-imported with:",
        "#   wsl --import <distro> C:\\WSL\\<distro> C:\\Backup\\<distro>.tar",
        "",
        "Write-Host '=== WSL VHDX Compaction ===' -ForegroundColor Cyan",
        "Write-Host '正在执行 VHDX 收缩，请勿中断...' -ForegroundColor Yellow",
        "",
    ]

    for vhdx in vhdx_paths:
        win_path = vhdx.replace("/mnt/c/", "C:\\").replace("/", "\\")
        lines += [
            f"$vhdx = '{win_path}'",
            "if (Test-Path $vhdx) {",
            f"    $before = (Get-Item $vhdx).Length",
            f"    Write-Host \"  正在收缩: $vhdx\" -ForegroundColor Gray",
            f"    Write-Host \"  收缩前大小: $([math]::Round($before/1GB, 2)) GB\"",
            "    try {",
            "        Optimize-VHD -Path $vhdx -Mode Full",
            "        $after = (Get-Item $vhdx).Length",
            "        $saved = $before - $after",
            f'        Write-Host \"  收缩完成! 释放: $([math]::Round($saved/1GB, 2)) GB\" -ForegroundColor Green',
            "    } catch {",
            f'        Write-Host \"  Optimize-VHD 失败: $_\" -ForegroundColor Red',
            "        Write-Host '  请确保: 1) WSL 已关闭  2) 以管理员身份运行' -ForegroundColor Yellow",
            "    }",
            "} else {",
            f'    Write-Host \"  VHDX 未找到: $vhdx\" -ForegroundColor Red',
            "}",
            "",
        ]

    lines += [
        "Write-Host '=== 所有 VHDX 处理完毕 ===' -ForegroundColor Cyan",
        "Read-Host '按 Enter 退出'",
    ]

    script = "\n".join(lines)
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(script)

    return output_path


def generate_template_script(output_path: str) -> str:
    """Generate manually-editable template"""
    script = """# WSL Storage Master — VHDX Compaction Template
# Run in Windows PowerShell (Admin)
# 1. Shutdown WSL first: wsl --shutdown
# 2. Modify VHDX paths below to actual paths
# 3. Run this script as Administrator

Write-Host '=== WSL VHDX Compaction ===' -ForegroundColor Cyan

# ----- Modify VHDX paths below -----
$vhdxPaths = @(
    "C:\\Users\\<YourUsername>\\AppData\\Local\\Packages\\<PackageName>\\LocalState\\ext4.vhdx"
)

foreach ($vhdx in $vhdxPaths) {
    if (Test-Path $vhdx) {
        $before = (Get-Item $vhdx).Length
        Write-Host "Shrinking: $vhdx" -ForegroundColor Gray
        Write-Host "Before: $([math]::Round($before/1GB, 2)) GB"
        Optimize-VHD -Path $vhdx -Mode Full
        $after = (Get-Item $vhdx).Length
        $saved = $before - $after
        Write-Host "Done! Freed: $([math]::Round($saved/1GB, 2)) GB" -ForegroundColor Green
    } else {
        Write-Host "NOT FOUND: $vhdx" -ForegroundColor Red
    }
}
Write-Host 'Done!' -ForegroundColor Cyan
Read-Host 'Press Enter to exit'
"""
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(script)
    return output_path
