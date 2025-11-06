"""
Configuration loader
"""

import yaml
from pathlib import Path


def load_config(config_file):
    """Laad configuratie van YAML file"""
    config_path = Path(config_file)

    if not config_path.exists():
        raise FileNotFoundError(f"Config file niet gevonden: {config_file}")

    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    # Valideer minimale configuratie
    required_keys = ['interface', 'thresholds', 'logging']
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Vereiste configuratie key ontbreekt: {key}")

    return config
