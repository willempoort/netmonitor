#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Sync missing environment variables from .env.example to .env

Usage:
    python sync_env.py              # Dry-run (show what would be added)
    python sync_env.py --apply      # Actually add missing variables
    python sync_env.py --help       # Show help
"""

import argparse
import os
import sys
from pathlib import Path


def parse_env_file(filepath: Path) -> dict:
    """Parse .env file into dictionary"""
    variables = {}
    if filepath.exists():
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    variables[key.strip()] = value.strip()
    return variables


def sync_env(env_file: str = ".env", example_file: str = ".env.example",
             apply: bool = False, verbose: bool = True):
    """
    Sync missing environment variables from .env.example to .env

    Args:
        env_file: Path to .env file
        example_file: Path to .env.example file
        apply: If True, actually add missing variables
        verbose: If True, print details

    Returns:
        List of (key, value) tuples that were added (or would be added)
    """
    env_path = Path(env_file)
    example_path = Path(example_file)

    if not example_path.exists():
        print(f"Error: {example_file} not found")
        return []

    # Parse both files
    example_vars = parse_env_file(example_path)
    current_vars = parse_env_file(env_path) if env_path.exists() else {}

    # Find missing variables
    missing = []
    for key, value in example_vars.items():
        if key not in current_vars:
            missing.append((key, value))

    if not missing:
        if verbose:
            print("✓ All variables from .env.example are present in .env")
        return []

    if verbose:
        print(f"Found {len(missing)} missing variable(s):\n")

    # Categorize by sensitivity
    sensitive_keywords = ['password', 'key', 'secret', 'token']

    for key, value in missing:
        is_sensitive = any(s in key.lower() for s in sensitive_keywords)
        display_value = "***" if is_sensitive else (value if value else "(empty)")

        if verbose:
            status = "→ Adding" if apply else "  Would add"
            print(f"  {status}: {key}={display_value}")

    if apply:
        # Create .env if it doesn't exist
        if not env_path.exists():
            env_path.touch()

        # Append missing variables
        with open(env_path, 'a') as f:
            f.write(f"\n# === Auto-synced from .env.example ===\n")
            for key, value in missing:
                f.write(f"{key}={value}\n")

        if verbose:
            print(f"\n✓ Added {len(missing)} variable(s) to {env_file}")
            print(f"  Please edit {env_file} to set your values")
    else:
        if verbose:
            print(f"\nTo apply these changes, run:")
            print(f"  python sync_env.py --apply")

    return missing


def main():
    parser = argparse.ArgumentParser(
        description="Sync missing environment variables from .env.example to .env"
    )
    parser.add_argument(
        '--apply',
        action='store_true',
        help='Actually add missing variables (default: dry-run)'
    )
    parser.add_argument(
        '--env',
        default='.env',
        help='Path to .env file (default: .env)'
    )
    parser.add_argument(
        '--example',
        default='.env.example',
        help='Path to .env.example file (default: .env.example)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode (no output)'
    )

    args = parser.parse_args()

    # Change to script directory if running from elsewhere
    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    missing = sync_env(
        env_file=args.env,
        example_file=args.example,
        apply=args.apply,
        verbose=not args.quiet
    )

    # Exit with code 0 if no missing vars, 1 if there are missing vars (for CI)
    sys.exit(0 if not missing or args.apply else 1)


if __name__ == '__main__':
    main()
