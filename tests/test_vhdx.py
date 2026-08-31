"""Tests for wsl_master.vhdx.helper — VHDX detection and script generation."""

import os
import subprocess
import pytest
from unittest.mock import patch, MagicMock
from wsl_master.vhdx.helper import (
    detect_wsl_instances, generate_shrink_script, generate_template_script,
)


def _make_wsl_result(stdout: str) -> MagicMock:
    """Create a mock subprocess.CompletedProcess for wsl.exe -l -v."""
    mock = MagicMock()
    mock.stdout = stdout.encode("utf-16-le")
    return mock


def _make_cmd_result(username: str) -> MagicMock:
    """Create a mock subprocess.CompletedProcess for cmd.exe whoami."""
    mock = MagicMock()
    mock.stdout = username.encode() if isinstance(username, str) else username
    return mock


class TestDetectWslInstancesParsing:
    """Verify wsl.exe -l -v output parsing."""

    WSL_OUTPUT = (
        "  NAME                   STATE           VERSION\r\n"
        "* Ubuntu-24.04           Running         2\r\n"
        "  Debian                 Stopped         2\r\n"
        "  docker-desktop         Stopped         2\r\n"
        "  docker-desktop-data    Stopped         2\r\n"
    )

    def test_parses_running_instance(self):
        mock_wsl = _make_wsl_result(self.WSL_OUTPUT)
        mock_cmd = _make_cmd_result("TestUser")
        # detect_wsl_instances calls wsl.exe once, then _find_vhdx_path
        # calls cmd.exe once per distro (4 distros). Need 1 + 4 = 5 returns.
        mocks = [mock_wsl] + [mock_cmd] * 4

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = mocks
            with patch("wsl_master.vhdx.helper.os.path.getsize", return_value=1024):
                with patch("pathlib.Path.exists", return_value=True):
                    with patch("pathlib.Path.iterdir", return_value=[]):
                        instances = detect_wsl_instances()

        assert len(instances) == 0  # no VHDX found because iterdir returns empty

    def test_parses_default_distro_with_star(self):
        mock_wsl = _make_wsl_result(self.WSL_OUTPUT)
        mock_cmd = _make_cmd_result("TestUser")
        mocks = [mock_wsl] + [mock_cmd] * 4

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = mocks
            with patch("pathlib.Path.is_dir", return_value=False):
                with patch("pathlib.Path.iterdir", return_value=[]):
                    instances = detect_wsl_instances()

        assert len(instances) == 0

    def test_no_wsl_installed_returns_empty(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            instances = detect_wsl_instances()
            assert instances == []

    def test_timeout_returns_empty(self):
        def _slow(*args, **kwargs):
            raise subprocess.TimeoutExpired("wsl.exe", 15)
        with patch("subprocess.run", side_effect=_slow):
            instances = detect_wsl_instances()
            assert instances == []

    def test_no_cmd_exe_returns_empty(self):
        mock_wsl = _make_wsl_result(self.WSL_OUTPUT)

        def _run_side_effect(cmd, **kwargs):
            if "wsl.exe" in cmd:
                return mock_wsl
            raise FileNotFoundError

        with patch("subprocess.run", side_effect=_run_side_effect):
            instances = detect_wsl_instances()
            assert instances == []


class TestDetectWslInstancesWithVhdx:
    """Test VHDX path detection with mocked filesystem."""

    def test_finds_vhdx_by_distro_name_match(self):
        mock_wsl = _make_wsl_result(
            "  NAME            STATE           VERSION\r\n"
            "  Ubuntu-24.04    Stopped         2\r\n"
        )
        mock_cmd = _make_cmd_result("TestUser")

        # Create mock iterdir entries
        pkg = MagicMock()
        pkg.is_dir.return_value = True
        pkg.name = "CanonicalGroupLimited.Ubuntu24.04LTS_xxxx"
        vhdx_file = MagicMock()
        vhdx_file.exists.return_value = True

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [mock_wsl, mock_cmd]
            with patch("pathlib.Path.iterdir", return_value=[pkg]):
                with patch("pathlib.Path.exists", return_value=True):
                    with patch.object(pkg, "__truediv__", return_value=vhdx_file):
                        with patch("os.path.getsize", return_value=1024):
                            instances = detect_wsl_instances()

        assert len(instances) >= 1
        if instances:
            assert instances[0].distro_name == "Ubuntu-24.04"
            assert instances[0].is_running is False


class TestDetectWslInstancesEdgeCases:
    """Edge cases for wsl.exe output parsing."""

    def test_distro_name_with_spaces(self):
        """Regex parser now correctly handles distro names with spaces."""
        mock_wsl = _make_wsl_result(
            "  NAME                       STATE           VERSION\r\n"
            "  Ubuntu 24.04 LTS           Running         2\r\n"
        )
        mock_cmd = _make_cmd_result("TestUser")
        mocks = [mock_wsl] + [mock_cmd]

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = mocks
            with patch("wsl_master.vhdx.helper._find_vhdx_path", return_value="/mnt/c/test.vhdx"):
                instances = detect_wsl_instances()

        assert len(instances) == 1
        assert instances[0].distro_name == "Ubuntu 24.04 LTS"
        assert instances[0].is_running is True

    def test_distro_name_with_periods(self):
        """openSUSE-Tumbleweed: the period causes split() to split wrongly."""
        mock_wsl = _make_wsl_result(
            "  NAME                          STATE           VERSION\r\n"
            "  openSUSE-Tumbleweed           Stopped         2\r\n"
        )
        mock_cmd = _make_cmd_result("TestUser")
        mocks = [mock_wsl] + [mock_cmd]

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = mocks
            with patch("wsl_master.vhdx.helper._find_vhdx_path", return_value="/mnt/c/test.vhdx"):
                instances = detect_wsl_instances()

        assert len(instances) == 1
        expected = "openSUSE-Tumbleweed"
        assert instances[0].distro_name == expected
        assert instances[0].is_running is False


class TestGenerateShrinkScript:
    """Verify PowerShell script generation."""

    def test_script_contains_vhdx_paths(self, tmp_path):
        output = tmp_path / "script.ps1"
        vhdx_paths = [
            "/mnt/c/Users/TestUser/AppData/Local/Packages/Ubuntu/LocalState/ext4.vhdx",
        ]
        result = generate_shrink_script(vhdx_paths, str(output))
        assert result == str(output)
        assert output.exists()
        content = output.read_text()
        assert "WSL Storage Master" in content
        assert "Optimize-VHD" in content
        win_path = vhdx_paths[0].replace("/mnt/c/", "C:\\").replace("/", "\\")
        assert win_path in content

    def test_script_uses_single_quotes_for_vhdx_var(self, tmp_path):
        output = tmp_path / "script_sq.ps1"
        vhdx_paths = [
            "/mnt/c/Users/Test/Packages/Ubuntu$Test/LocalState/ext4.vhdx",
        ]
        generate_shrink_script(vhdx_paths, str(output))
        content = output.read_text()
        assert "$vhdx = '" in content
        assert "Ubuntu$Test" in content
        assert content.count("'") >= 2

    def test_script_empty_paths(self, tmp_path):
        output = tmp_path / "empty.ps1"
        generate_shrink_script([], str(output))
        content = output.read_text()
        assert "=== WSL VHDX Compaction ===" in content

    def test_script_header_and_footer(self, tmp_path):
        output = tmp_path / "full.ps1"
        vhdx_paths = ["/mnt/c/test/path.vhdx"]
        generate_shrink_script(vhdx_paths, str(output))
        content = output.read_text()
        assert "Write-Host '=== WSL VHDX Compaction ==='" in content
        assert "按 Enter 退出" in content

    def test_script_creates_parent_dirs(self, tmp_path):
        output = tmp_path / "deep" / "nested" / "script.ps1"
        vhdx_paths = ["/mnt/c/test/path.vhdx"]
        generate_shrink_script(vhdx_paths, str(output))
        assert output.exists()


class TestGenerateTemplateScript:
    """Verify template script generation."""

    def test_template_contains_instructions(self, tmp_path):
        output = tmp_path / "template.ps1"
        result = generate_template_script(str(output))
        assert result == str(output)
        content = output.read_text()
        assert "WSL Storage Master" in content
        assert "Compaction Template" in content
        assert "Modify VHDX paths below" in content


class TestVhdxPathConversion:
    """WSL path to Windows path conversion in scripts."""

    def test_basic_path_conversion(self, tmp_path):
        output = tmp_path / "path_test.ps1"
        linux_path = "/mnt/c/Users/X/AppData/Local/Packages/Pkg/LocalState/ext4.vhdx"
        generate_shrink_script([linux_path], str(output))
        content = output.read_text()
        win_path = linux_path.replace("/mnt/c/", "C:\\").replace("/", "\\")
        assert win_path in content

    def test_path_with_special_chars(self, tmp_path):
        output = tmp_path / "special.ps1"
        vhdx_paths = ["/mnt/c/Program Files/App/test.vhdx"]
        generate_shrink_script(vhdx_paths, str(output))
        content = output.read_text()
        assert "Program Files" in content
