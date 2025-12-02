#!/bin/bash
################################################################################
# 2FA Secret Recovery Script
# Use this if you enabled 2FA during setup but can't log in
################################################################################

echo "========================================================================"
echo "🔐 TWO-FACTOR AUTHENTICATION SETUP"
echo "========================================================================"
echo
echo "Retrieving your 2FA secret from the database..."
echo

# Get database config from config.yaml
DB_HOST=$(grep -A 5 "postgresql:" config.yaml | grep "host:" | awk '{print $2}')
DB_PORT=$(grep -A 5 "postgresql:" config.yaml | grep "port:" | awk '{print $2}')
DB_NAME=$(grep -A 5 "postgresql:" config.yaml | grep "database:" | awk '{print $2}')
DB_USER=$(grep -A 5 "postgresql:" config.yaml | grep "user:" | awk '{print $2}')
DB_PASS=$(grep -A 5 "postgresql:" config.yaml | grep "password:" | awk '{print $2}')

# Set defaults if not found
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_NAME=${DB_NAME:-netmonitor}
DB_USER=${DB_USER:-netmonitor}
DB_PASS=${DB_PASS:-netmonitor}

# Query database
RESULT=$(PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -A -c \
  "SELECT username, totp_secret FROM web_users WHERE totp_enabled = TRUE;")

if [ -z "$RESULT" ]; then
    echo "❌ No users with 2FA enabled found"
    exit 1
fi

echo "Found user(s) with 2FA enabled:"
echo

# Parse result
while IFS='|' read -r username secret; do
    echo "========================================================================"
    echo "User: $username"
    echo "========================================================================"
    echo
    echo "Your 2FA Secret Key: $secret"
    echo
    echo "----------------------------------------------------------------------"
    echo "MANUAL SETUP INSTRUCTIONS"
    echo "----------------------------------------------------------------------"
    echo
    echo "1. Open your authenticator app (Google Authenticator, Authy, etc.)"
    echo "2. Select 'Add account' or '+'"
    echo "3. Choose 'Enter setup key' or 'Manual entry'"
    echo "4. Enter the following details:"
    echo
    echo "   Account name:  NetMonitor SOC ($username)"
    echo "   Secret key:    $secret"
    echo "   Type:          Time-based"
    echo "   Digits:        6"
    echo "   Period:        30 seconds"
    echo
    echo "5. Save the account"
    echo "6. Your app will now generate 6-digit codes every 30 seconds"
    echo "7. Use these codes when logging in to the dashboard"
    echo
    echo "========================================================================"
    echo
done <<< "$RESULT"

echo "----------------------------------------------------------------------"
echo "⚠️  SECURITY WARNING"
echo "----------------------------------------------------------------------"
echo
echo "• NEVER share your 2FA secret with anyone"
echo "• Store it securely (e.g., in a password manager)"
echo "• Get backup codes from the dashboard after logging in"
echo
echo "========================================================================"
echo
