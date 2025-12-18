#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
2FA QR Code Display Script
Shows the 2FA QR code for a user who has 2FA enabled but hasn't set it up yet
"""

import sys
from pathlib import Path
import pyotp
import qrcode
import io

# Add current dir to path
sys.path.insert(0, str(Path(__file__).parent))

from config_loader import load_config
from database import DatabaseManager
from env_loader import get_db_config
import os


def display_qr_code(username: str):
    """Display 2FA QR code for a user"""

    # Load config (still needed for other settings)
    try:
        config = load_config('config.yaml')
    except Exception as e:
        print(f"❌ Error loading config: {e}")
        sys.exit(1)

    # Connect to database - prefer .env over config.yaml
    try:
        if os.path.exists('.env'):
            db_config = get_db_config()
            print("ℹ️  Using credentials from .env")
        else:
            db_config_yaml = config.get('database', {}).get('postgresql', {})
            db_config = {
                'host': db_config_yaml.get('host', 'localhost'),
                'port': db_config_yaml.get('port', 5432),
                'database': db_config_yaml.get('database', 'netmonitor'),
                'user': db_config_yaml.get('user', 'netmonitor'),
                'password': db_config_yaml.get('password', 'netmonitor')
            }
            print("ℹ️  Using credentials from config.yaml")

        db = DatabaseManager(**db_config)
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        sys.exit(1)

    # Get user from database
    conn = db._get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, email, totp_secret, totp_enabled
            FROM web_users
            WHERE username = %s
        ''', (username,))

        result = cursor.fetchone()
        if not result:
            print(f"❌ User '{username}' not found")
            sys.exit(1)

        user_id, username, email, totp_secret, totp_enabled = result

        if not totp_enabled:
            print(f"⚠️  User '{username}' does not have 2FA enabled")
            sys.exit(1)

        if not totp_secret:
            print(f"❌ User '{username}' has 2FA enabled but no secret in database")
            sys.exit(1)

    except Exception as e:
        print(f"❌ Error querying user: {e}")
        sys.exit(1)
    finally:
        db._return_connection(conn)

    # Generate provisioning URI
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(
        name=username,
        issuer_name="NetMonitor SOC"
    )

    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    # Print header
    print("=" * 70)
    print("🔐 TWO-FACTOR AUTHENTICATION SETUP")
    print("=" * 70)
    print()
    print(f"User: {username}")
    print(f"Email: {email or '(none)'}")
    print()
    print("Scan this QR code with your authenticator app:")
    print("(Google Authenticator, Authy, Microsoft Authenticator, etc.)")
    print()

    # Print QR code as ASCII art
    qr.print_ascii(invert=True)

    print()
    print("=" * 70)
    print("ALTERNATIVE: Manual Entry")
    print("=" * 70)
    print()
    print("If you can't scan the QR code, manually enter this secret in your app:")
    print()
    print(f"  Secret Key: {totp_secret}")
    print()
    print("Settings:")
    print("  - Account name: NetMonitor SOC ({})".format(username))
    print("  - Type: Time-based")
    print("  - Digits: 6")
    print("  - Period: 30 seconds")
    print()
    print("=" * 70)
    print("⚠️  SECURITY WARNING")
    print("=" * 70)
    print()
    print("This script displays your 2FA secret for INITIAL SETUP ONLY.")
    print("After scanning the QR code or entering the secret:")
    print()
    print("  1. Test that your authenticator app generates working codes")
    print("  2. Log in to the dashboard to verify 2FA works")
    print("  3. Save your backup codes from the dashboard")
    print("  4. NEVER share your 2FA secret with anyone!")
    print()


def main():
    """Main function"""
    print()

    if len(sys.argv) != 2:
        print("Usage: python3 show_2fa_qr.py <username>")
        print()
        print("This script displays the 2FA QR code for a user who has")
        print("2FA enabled but hasn't completed the initial setup.")
        print()
        sys.exit(1)

    username = sys.argv[1].strip()

    if not username:
        print("❌ Username cannot be empty")
        sys.exit(1)

    try:
        display_qr_code(username)
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
