#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Environment Variable Loader
Loads environment variables from .env file
"""

import os
from pathlib import Path
from typing import Optional, Dict


def load_env(env_file: str = '.env', base_path: Optional[str] = None) -> Dict[str, str]:
    """
    Load environment variables from .env file

    Args:
        env_file: Name of env file (default: .env)
        base_path: Base directory to search for .env (default: script directory)

    Returns:
        Dictionary with environment variables
    """
    if base_path is None:
        # Try current directory first, then script directory
        if os.path.exists(env_file):
            env_path = Path(env_file)
        else:
            env_path = Path(__file__).parent / env_file
    else:
        env_path = Path(base_path) / env_file

    env_vars = {}

    if not env_path.exists():
        return env_vars

    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Parse KEY=VALUE
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                # Remove quotes if present
                if value and value[0] in ('"', "'") and value[-1] in ('"', "'"):
                    value = value[1:-1]

                env_vars[key] = value

    return env_vars


def get_env(key: str, default: Optional[str] = None, env_file: str = '.env') -> Optional[str]:
    """
    Get a single environment variable

    Priority:
    1. os.environ (already set)
    2. .env file
    3. default value

    Args:
        key: Environment variable name
        default: Default value if not found
        env_file: Name of env file to check

    Returns:
        Value of environment variable or default
    """
    # First check if it's already in environment
    if key in os.environ:
        return os.environ[key]

    # Check .env file
    env_vars = load_env(env_file)
    return env_vars.get(key, default)


def load_env_into_environ(env_file: str = '.env', override: bool = False) -> int:
    """
    Load .env file into os.environ

    Args:
        env_file: Name of env file
        override: Whether to override existing environment variables

    Returns:
        Number of variables loaded
    """
    env_vars = load_env(env_file)
    count = 0

    for key, value in env_vars.items():
        if override or key not in os.environ:
            os.environ[key] = value
            count += 1

    return count


def get_db_config(env_file: str = '.env') -> Dict[str, any]:
    """
    Get database configuration from .env file or environment variables

    Returns:
        Dictionary with database configuration
    """
    env_vars = load_env(env_file)

    return {
        'host': get_env('DB_HOST', 'localhost', env_file),
        'port': int(get_env('DB_PORT', '5432', env_file)),
        'database': get_env('DB_NAME', 'netmonitor', env_file),
        'user': get_env('DB_USER', 'netmonitor', env_file),
        'password': get_env('DB_PASSWORD', 'netmonitor', env_file)
    }


# Auto-load .env when module is imported (unless disabled)
if os.environ.get('NETMONITOR_DISABLE_AUTOLOAD_ENV') != '1':
    try:
        count = load_env_into_environ(override=False)
        if count > 0 and os.environ.get('DEBUG') == '1':
            print(f"[env_loader] Loaded {count} variables from .env")
    except Exception:
        # Silently fail if .env doesn't exist
        pass
