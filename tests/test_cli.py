"""Tests for CLI argument parsing and cmd_clean dry-run logic."""

import pytest
import argparse
from unittest.mock import patch, MagicMock
import sqlite3


class TestCleanDryRunLogic:
    """Verify the dry_run variable in cmd_clean is set correctly.

    This tests the actual logic pattern used in cmd_clean (before fix)
    to prove the bug exists and the fix works.
    """

    def test_buggy_logic_always_returns_true(self):
        """The current buggy line: hasattr(args,'no_dry_run') is always False."""
        # Simulate what argparse produces when user passes --no-dry-run
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        p = sub.add_parser("clean")
        p.add_argument("--dry-run", action="store_true", default=True)
        p.add_argument("--no-dry-run", action="store_false", dest="dry_run")

        args = parser.parse_args(["clean", "--no-dry-run"])

        # BUGGY LINE (current code):
        dry_run = not hasattr(args, 'no_dry_run') or getattr(args, 'dry_run', True)

        # With --no-dry-run, this SHOULD be False but the bug makes it True
        assert dry_run is True, (
            "BUG CONFIRMED: dry_run is True even with --no-dry-run! "
            "Because hasattr(args, 'no_dry_run') is always False "
            "(dest='dry_run' stores the value under args.dry_run, not args.no_dry_run)"
        )

    def test_fixed_logic_uses_args_dry_run_directly_with_no_flag(self):
        """Fix: directly use args.dry_run. Without --no-dry-run -> dry_run=True."""
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        p = sub.add_parser("clean")
        p.add_argument("--no-dry-run", action="store_false", dest="dry_run", default=True)

        args = parser.parse_args(["clean"])

        # FIXED: use args.dry_run directly
        dry_run = args.dry_run
        assert dry_run is True

    def test_fixed_logic_uses_args_dry_run_directly_with_no_dry_run(self):
        """Fix: directly use args.dry_run. With --no-dry-run -> dry_run=False."""
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        p = sub.add_parser("clean")
        p.add_argument("--no-dry-run", action="store_false", dest="dry_run", default=True)

        args = parser.parse_args(["clean", "--no-dry-run"])

        # FIXED: use args.dry_run directly
        dry_run = args.dry_run
        assert dry_run is False
