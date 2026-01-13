#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Configuration Management for MCP Streamable HTTP Server

Loads configuration from environment variables with sensible defaults.
"""

import os
from typing import Dict, Any


def load_config() -> Dict[str, Any]:
    """
    Load configuration from environment variables

    Returns:
        Dictionary with all configuration settings
    """

    return {
        # Server settings
        'debug': os.getenv('MCP_DEBUG', 'false').lower() == 'true',
        'host': os.getenv('MCP_API_HOST', '127.0.0.1'),
        'port': int(os.getenv('MCP_API_PORT', '8000')),
        'log_level': os.getenv('LOG_LEVEL', 'INFO'),

        # Database settings
        'database': {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', '5432')),
            'database': os.getenv('DB_NAME', 'netmonitor'),
            'user': os.getenv('DB_USER', 'mcp_readonly'),
            'password': os.getenv('DB_PASSWORD', 'mcp_netmonitor_readonly_2024'),
        },

        # Ollama settings
        'ollama': {
            'base_url': os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434'),
            'model': os.getenv('OLLAMA_MODEL', 'llama3.2'),
        },

        # MCP protocol settings
        'mcp': {
            'endpoint_path': os.getenv('MCP_ENDPOINT_PATH', '/mcp'),
            'stateless': os.getenv('MCP_STATELESS', 'true').lower() == 'true',
            'json_response': os.getenv('MCP_JSON_RESPONSE', 'false').lower() == 'true',
        },

        # CORS settings
        'cors': {
            'enabled': os.getenv('MCP_CORS_ENABLED', 'true').lower() == 'true',
            'origins': os.getenv('MCP_CORS_ORIGINS', '*').split(','),
        },

        # Authentication settings
        'auth': {
            'required': os.getenv('MCP_AUTH_REQUIRED', 'true').lower() == 'true',
            'rate_limit_enabled': os.getenv('MCP_RATE_LIMIT_ENABLED', 'true').lower() == 'true',
        }
    }


def get_database_config() -> Dict[str, Any]:
    """
    Get database configuration specifically

    Returns:
        Database connection parameters
    """
    config = load_config()
    return config['database']


def get_ollama_config() -> Dict[str, Any]:
    """
    Get Ollama configuration specifically

    Returns:
        Ollama client parameters
    """
    config = load_config()
    return config['ollama']


def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate configuration settings

    Args:
        config: Configuration dictionary to validate

    Returns:
        True if valid, raises ValueError if invalid
    """
    # Validate port range
    port = config.get('port')
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"Invalid port: {port}. Must be between 1 and 65535")

    # Validate database port
    db_port = config['database'].get('port')
    if not isinstance(db_port, int) or not (1 <= db_port <= 65535):
        raise ValueError(f"Invalid database port: {db_port}")

    # Validate log level
    valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    log_level = config.get('log_level', '').upper()
    if log_level not in valid_log_levels:
        raise ValueError(f"Invalid log level: {log_level}. Must be one of {valid_log_levels}")

    # Validate required database fields
    required_db_fields = ['host', 'port', 'database', 'user', 'password']
    for field in required_db_fields:
        if not config['database'].get(field):
            raise ValueError(f"Missing required database field: {field}")

    return True


if __name__ == "__main__":
    # Test configuration loading
    try:
        config = load_config()
        validate_config(config)
        print("✅ Configuration loaded and validated successfully")
        print(f"   Server: {config['host']}:{config['port']}")
        print(f"   Database: {config['database']['database']}@{config['database']['host']}")
        print(f"   Ollama: {config['ollama']['base_url']}")
        print(f"   Debug: {config['debug']}")
        print(f"   Auth required: {config['auth']['required']}")
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        exit(1)
