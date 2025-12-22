#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Sync missing configuration sections from config_defaults.py to config.yaml

Usage:
    python sync_config.py              # Dry-run (show what would be added)
    python sync_config.py --apply      # Actually add missing sections
    python sync_config.py --help       # Show help
"""

import argparse
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Tuple

import yaml

# Import defaults
try:
    from config_defaults import BEST_PRACTICE_CONFIG, PARAMETER_DESCRIPTIONS
except ImportError:
    print("Error: Could not import config_defaults.py")
    sys.exit(1)


# Sections that should be synced (with comments)
SECTION_COMMENTS = {
    'integrations': """
# =============================================================================
# INTEGRATIONS - SIEM & Threat Intelligence (optional)
# =============================================================================
# All integrations are disabled by default.
# Credentials come from .env file (MISP_API_KEY, WAZUH_API_PASSWORD, etc.)
# See: docs/features/INTEGRATIONS.md
""",
    'threat_feeds': """
# =============================================================================
# THREAT FEEDS - IOC feeds for threat detection
# =============================================================================
""",
    'alerts': """
# =============================================================================
# ALERT MANAGEMENT - How alerts are processed and sent
# =============================================================================
""",
    'performance': """
# =============================================================================
# PERFORMANCE - Timing and intervals
# =============================================================================
""",
    'abuseipdb': """
# =============================================================================
# ABUSEIPDB - IP reputation lookups (requires API key in .env)
# =============================================================================
""",
}


def find_missing_sections(user_config: Dict, defaults: Dict) -> List[str]:
    """Find top-level sections that are missing from user config"""
    missing = []
    for key in defaults:
        if key not in user_config:
            missing.append(key)
    return missing


def dict_to_yaml_with_disabled(config: Dict, indent: int = 0) -> str:
    """
    Convert dict to YAML string with all 'enabled' fields set to false.
    Also converts empty strings to commented placeholders.
    """
    lines = []
    prefix = "  " * indent

    for key, value in config.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.append(dict_to_yaml_with_disabled(value, indent + 1))
        elif isinstance(value, list):
            if len(value) == 0:
                lines.append(f"{prefix}{key}: []")
            else:
                lines.append(f"{prefix}{key}:")
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f"{prefix}  -")
                        for k, v in item.items():
                            lines.append(f"{prefix}    {k}: {format_value(v)}")
                    else:
                        lines.append(f"{prefix}  - {format_value(item)}")
        elif key == 'enabled':
            # Always set enabled to false for new sections
            lines.append(f"{prefix}{key}: false")
        elif value == '' or value is None:
            # Empty values - add comment about .env
            env_hint = get_env_hint(key)
            if env_hint:
                lines.append(f"{prefix}{key}: \"\"  # Set in .env: {env_hint}")
            else:
                lines.append(f"{prefix}{key}: \"\"")
        else:
            lines.append(f"{prefix}{key}: {format_value(value)}")

    return "\n".join(lines)


def format_value(value: Any) -> str:
    """Format a value for YAML output"""
    if isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, str):
        if value == '':
            return '""'
        # Quote strings with special chars
        if any(c in value for c in [':', '#', '{', '}', '[', ']', ',', '&', '*', '?', '|', '-', '<', '>', '=', '!', '%', '@', '`']):
            return f'"{value}"'
        return value
    elif value is None:
        return '""'
    else:
        return str(value)


def get_env_hint(key: str) -> str:
    """Get environment variable hint for a key"""
    env_mapping = {
        'api_key': 'MISP_API_KEY / OTX_API_KEY / ABUSEIPDB_API_KEY',
        'api_password': 'WAZUH_API_PASSWORD',
        'api_user': 'WAZUH_API_USER',
        'api_url': 'WAZUH_API_URL / MISP_URL',
        'url': 'MISP_URL',
        'host': 'SYSLOG_HOST',
    }
    return env_mapping.get(key, '')


def sync_config(config_file: str = "config.yaml", apply: bool = False,
                verbose: bool = True) -> List[str]:
    """
    Sync missing configuration sections from defaults to config.yaml

    Args:
        config_file: Path to config.yaml
        apply: If True, actually modify the file
        verbose: If True, print details

    Returns:
        List of section names that were (or would be) added
    """
    config_path = Path(config_file)

    if not config_path.exists():
        print(f"Error: {config_file} not found")
        return []

    # Load current config
    with open(config_path, 'r') as f:
        content = f.read()
        user_config = yaml.safe_load(content) or {}

    # Find missing sections
    missing = find_missing_sections(user_config, BEST_PRACTICE_CONFIG)

    if not missing:
        if verbose:
            print("✓ All sections from config_defaults.py are present in config.yaml")
        return []

    if verbose:
        print(f"Found {len(missing)} missing section(s):\n")

    sections_to_add = []

    for section in missing:
        if verbose:
            status = "→ Adding" if apply else "  Would add"
            print(f"  {status}: {section}")

        # Get the section config from defaults
        section_config = BEST_PRACTICE_CONFIG[section]

        # Generate YAML for this section
        comment = SECTION_COMMENTS.get(section, f"\n# === {section.upper()} ===\n")
        yaml_content = dict_to_yaml_with_disabled({section: section_config})

        sections_to_add.append((section, comment + yaml_content))

    if apply:
        # Append missing sections to config file
        with open(config_path, 'a') as f:
            f.write("\n")
            for section, yaml_content in sections_to_add:
                f.write(yaml_content)
                f.write("\n")

        if verbose:
            print(f"\n✓ Added {len(missing)} section(s) to {config_file}")
            print(f"  Review the file and enable sections as needed")
    else:
        if verbose:
            print(f"\nTo apply these changes, run:")
            print(f"  python sync_config.py --apply")

    return missing


def show_section_preview(section: str):
    """Show a preview of what a section would look like"""
    if section not in BEST_PRACTICE_CONFIG:
        print(f"Unknown section: {section}")
        return

    section_config = BEST_PRACTICE_CONFIG[section]
    comment = SECTION_COMMENTS.get(section, f"\n# === {section.upper()} ===\n")
    yaml_content = dict_to_yaml_with_disabled({section: section_config})

    print(comment + yaml_content)


def main():
    parser = argparse.ArgumentParser(
        description="Sync missing configuration sections from config_defaults.py to config.yaml"
    )
    parser.add_argument(
        '--apply',
        action='store_true',
        help='Actually add missing sections (default: dry-run)'
    )
    parser.add_argument(
        '--config',
        default='config.yaml',
        help='Path to config.yaml (default: config.yaml)'
    )
    parser.add_argument(
        '--preview',
        metavar='SECTION',
        help='Preview a specific section (e.g., --preview integrations)'
    )
    parser.add_argument(
        '--list',
        action='store_true',
        help='List all available sections in config_defaults.py'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode (no output)'
    )

    args = parser.parse_args()

    # Change to script directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    if args.list:
        print("Available sections in config_defaults.py:\n")
        for section in BEST_PRACTICE_CONFIG:
            desc = SECTION_COMMENTS.get(section, '').strip().split('\n')[0] if section in SECTION_COMMENTS else ''
            print(f"  {section}")
        return

    if args.preview:
        show_section_preview(args.preview)
        return

    missing = sync_config(
        config_file=args.config,
        apply=args.apply,
        verbose=not args.quiet
    )

    # Exit with code 0 if no missing sections, 1 if there are (for CI)
    sys.exit(0 if not missing or args.apply else 1)


if __name__ == '__main__':
    main()
