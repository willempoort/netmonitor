#!/usr/bin/env python3
"""
Setup Admin User Script
Create the first administrator account for NetMonitor web dashboard
"""

import sys
import getpass
from pathlib import Path

# Add current dir to path
sys.path.insert(0, str(Path(__file__).parent))

from config_loader import load_config
from database import DatabaseManager
from web_auth import WebAuthManager


def validate_password(password):
    """Validate password strength"""
    if len(password) < 12:
        return False, "Password must be at least 12 characters"

    # Check for complexity
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)

    if not (has_upper and has_lower and has_digit):
        return False, "Password must contain uppercase, lowercase, and digit"

    return True, "Password is strong"


def main():
    print("=" * 70)
    print("NetMonitor - Admin User Setup")
    print("=" * 70)
    print()
    print("This script will create an administrator account for the web dashboard.")
    print()

    # Load config
    try:
        config = load_config('config.yaml')
    except Exception as e:
        print(f"❌ Error loading config: {e}")
        sys.exit(1)

    # Connect to database
    print("[1/4] Connecting to database...")
    try:
        db_config = config.get('database', {}).get('postgresql', {})
        db = DatabaseManager(
            host=db_config.get('host', 'localhost'),
            port=db_config.get('port', 5432),
            database=db_config.get('database', 'netmonitor'),
            user=db_config.get('user', 'netmonitor'),
            password=db_config.get('password', 'netmonitor')
        )
        print("✓ Database connected")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        sys.exit(1)

    print()

    # Initialize auth manager
    print("[2/4] Initializing authentication manager...")
    try:
        auth = WebAuthManager(db)
        print("✓ Auth manager ready")
    except Exception as e:
        print(f"❌ Auth manager failed: {e}")
        sys.exit(1)

    print()

    # Check if admin users already exist
    try:
        users = auth.list_users()
        admin_users = [u for u in users if u['role'] == 'admin' and u['is_active']]

        if admin_users:
            print("⚠️  WARNING: Admin users already exist:")
            for user in admin_users:
                print(f"   - {user['username']} ({user['email'] or 'no email'})")
            print()

            response = input("Do you want to create another admin user? (y/N): ").strip().lower()
            if response != 'y':
                print("Aborted.")
                sys.exit(0)
    except Exception as e:
        print(f"⚠️  Warning: Could not check existing users: {e}")

    print()

    # Get user details
    print("[3/4] Enter administrator details")
    print("-" * 70)

    # Username
    while True:
        username = input("Username: ").strip()
        if not username:
            print("❌ Username cannot be empty")
            continue

        if len(username) < 3:
            print("❌ Username must be at least 3 characters")
            continue

        # Check if username exists
        existing_user = auth.get_user_by_username(username)
        if existing_user:
            print(f"❌ Username '{username}' already exists")
            continue

        break

    # Email (optional)
    email = input("Email (optional): ").strip() or None

    # Password
    while True:
        password = getpass.getpass("Password: ")

        if not password:
            print("❌ Password cannot be empty")
            continue

        valid, message = validate_password(password)
        if not valid:
            print(f"❌ {message}")
            continue

        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            print("❌ Passwords do not match")
            continue

        break

    # Enable 2FA
    print()
    print("Two-Factor Authentication (2FA) adds extra security to your account.")
    print("You can enable it now or later from the dashboard.")
    enable_2fa = input("Enable 2FA now? (y/N): ").strip().lower() == 'y'

    print()
    print("-" * 70)
    print("Summary:")
    print(f"  Username: {username}")
    print(f"  Email:    {email or '(none)'}")
    print(f"  Role:     admin")
    print(f"  2FA:      {'Enabled' if enable_2fa else 'Disabled'}")
    print("-" * 70)
    print()

    response = input("Create this admin user? (y/N): ").strip().lower()
    if response != 'y':
        print("Aborted.")
        sys.exit(0)

    # Create user
    print()
    print("[4/4] Creating admin user...")
    try:
        user = auth.create_user(
            username=username,
            password=password,
            email=email,
            role='admin',
            created_by='setup_script',
            enable_2fa=enable_2fa
        )

        if not user:
            print("❌ Failed to create user")
            sys.exit(1)

        print(f"✓ Admin user '{username}' created successfully!")
        print()

        # Show 2FA details if enabled
        if enable_2fa and user.totp_enabled and user.totp_secret:
            print("=" * 70)
            print("⚠️  TWO-FACTOR AUTHENTICATION SETUP - ACTION REQUIRED!")
            print("=" * 70)
            print()
            print("Your account has been created with 2FA enabled.")
            print("You MUST complete this setup NOW before you can log in!")
            print()
            print("-" * 70)
            print("STEP 1: Add to your authenticator app")
            print("-" * 70)
            print()
            print("Open your authenticator app (Google Authenticator, Authy, Microsoft")
            print("Authenticator, etc.) and add a new account with these details:")
            print()
            print(f"  Account name:  NetMonitor SOC ({username})")
            print(f"  Secret key:    {user.totp_secret}")
            print(f"  Type:          Time-based")
            print(f"  Digits:        6")
            print(f"  Period:        30 seconds")
            print()
            print("Your app will now generate 6-digit codes every 30 seconds.")
            print()
            print("-" * 70)
            print("STEP 2: Test the setup")
            print("-" * 70)
            print()
            print("Before closing this window:")
            print("  1. Check that your authenticator app shows a 6-digit code")
            print("  2. Make sure the account name shows 'NetMonitor SOC'")
            print("  3. Write down this secret key in a secure location (password manager)")
            print()
            print("-" * 70)
            print("🔒 SECURITY NOTES")
            print("-" * 70)
            print()
            print("• This secret is shown ONLY ONCE during initial setup")
            print("• Store it securely (e.g., in a password manager)")
            print("• NEVER share it with anyone")
            print("• You will need the 6-digit code from your app to log in")
            print("• Get backup codes from the dashboard after logging in")
            print()

        # Login instructions
        print("=" * 70)
        print("✓ SETUP COMPLETE!")
        print("=" * 70)
        print()
        print("You can now log in to the NetMonitor dashboard:")
        print()
        print("  URL:      http://localhost:8181/")
        print(f"  Username: {username}")
        print(f"  Password: (the password you just entered)")

        if enable_2fa:
            print(f"  2FA Code: (6-digit code from your authenticator app)")

        print()
        print("To start the dashboard:")
        print("  python3 web_dashboard.py")
        print()

    except Exception as e:
        print(f"❌ Error creating user: {e}")
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
