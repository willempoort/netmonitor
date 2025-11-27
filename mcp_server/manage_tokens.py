#!/usr/bin/env python3
"""
MCP API Token Management CLI

Command-line tool for managing API tokens for the MCP HTTP server.
"""

import os
import sys
import argparse
from datetime import datetime
from pathlib import Path
from tabulate import tabulate

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from token_auth import TokenAuthManager


def create_token_manager():
    """Create token manager instance"""
    host = os.environ.get('NETMONITOR_DB_HOST', 'localhost')
    port = int(os.environ.get('NETMONITOR_DB_PORT', '5432'))
    database = os.environ.get('NETMONITOR_DB_NAME', 'netmonitor')
    user = os.environ.get('NETMONITOR_DB_USER', 'netmonitor')
    password = os.environ.get('NETMONITOR_DB_PASSWORD', 'netmonitor')

    return TokenAuthManager({
        'host': host,
        'port': port,
        'database': database,
        'user': user,
        'password': password
    })


def cmd_create(args):
    """Create a new API token"""
    manager = create_token_manager()

    try:
        result = manager.create_token(
            name=args.name,
            description=args.description or "",
            scope=args.scope,
            rate_limit_per_minute=args.rate_minute,
            rate_limit_per_hour=args.rate_hour,
            rate_limit_per_day=args.rate_day,
            expires_in_days=args.expires_days,
            created_by=args.created_by
        )

        print("\n✅ API Token created successfully!")
        print(f"\n🔑 Token: {result['token']}")
        print("\n⚠️  IMPORTANT: Save this token now - it cannot be retrieved later!\n")
        print(f"   Name:        {result['name']}")
        print(f"   Scope:       {result['scope']}")
        print(f"   Created:     {result['created_at']}")
        if result['expires_at']:
            print(f"   Expires:     {result['expires_at']}")
        print("\n📋 Usage example:")
        print(f"   curl -H 'Authorization: Bearer {result['token']}' http://localhost:8000/mcp/tools\n")

    except Exception as e:
        print(f"\n❌ Error creating token: {e}\n")
        sys.exit(1)


def cmd_list(args):
    """List all API tokens"""
    manager = create_token_manager()

    try:
        tokens = manager.list_tokens(include_disabled=args.all)

        if not tokens:
            print("\nNo tokens found.\n")
            return

        # Prepare table data
        headers = ["ID", "Name", "Scope", "Enabled", "Requests", "Last Used", "Created", "Expires"]
        rows = []

        for token in tokens:
            last_used = token['last_used_at'].strftime('%Y-%m-%d %H:%M') if token['last_used_at'] else 'Never'
            created = token['created_at'].strftime('%Y-%m-%d %H:%M') if token['created_at'] else '-'
            expires = token['expires_at'].strftime('%Y-%m-%d') if token['expires_at'] else 'Never'

            # Check if expired
            expired = ""
            if token['expires_at'] and token['expires_at'] < datetime.now():
                expired = " (EXPIRED)"

            rows.append([
                token['id'],
                token['name'][:30],
                token['scope'],
                '✓' if token['enabled'] else '✗',
                token['request_count'] or 0,
                last_used,
                created,
                expires + expired
            ])

        print("\n" + tabulate(rows, headers=headers, tablefmt='grid'))
        print(f"\nTotal: {len(tokens)} token(s)\n")

    except Exception as e:
        print(f"\n❌ Error listing tokens: {e}\n")
        sys.exit(1)


def cmd_show(args):
    """Show detailed token information"""
    manager = create_token_manager()

    try:
        # Get token info
        tokens = manager.list_tokens(include_disabled=True)
        token = next((t for t in tokens if t['id'] == args.token_id), None)

        if not token:
            print(f"\n❌ Token ID {args.token_id} not found.\n")
            sys.exit(1)

        # Get stats
        stats = manager.get_token_stats(args.token_id)

        print("\n" + "="*60)
        print(f"API Token Details - ID: {token['id']}")
        print("="*60)
        print(f"\n📋 Basic Information:")
        print(f"   Name:             {token['name']}")
        print(f"   Description:      {token['description'] or '(none)'}")
        print(f"   Scope:            {token['scope']}")
        print(f"   Enabled:          {'Yes ✓' if token['enabled'] else 'No ✗'}")

        print(f"\n⚡ Rate Limits:")
        print(f"   Per Minute:       {token['rate_limit_per_minute'] or 'Unlimited'}")
        print(f"   Per Hour:         {token['rate_limit_per_hour'] or 'Unlimited'}")
        print(f"   Per Day:          {token['rate_limit_per_day'] or 'Unlimited'}")

        print(f"\n📊 Usage Statistics:")
        print(f"   Total Requests:   {stats.get('total_requests', 0)}")
        print(f"   Last Hour:        {stats.get('requests_last_hour', 0)}")
        print(f"   Last 24h:         {stats.get('requests_last_day', 0)}")
        print(f"   Errors:           {stats.get('error_count', 0)}")
        avg_time = stats.get('avg_response_time_ms')
        if avg_time:
            print(f"   Avg Response:     {avg_time:.1f} ms")

        print(f"\n📅 Timestamps:")
        print(f"   Created:          {token['created_at'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Created By:       {token['created_by'] or '(unknown)'}")
        last_used = token['last_used_at'].strftime('%Y-%m-%d %H:%M:%S') if token['last_used_at'] else 'Never'
        print(f"   Last Used:        {last_used}")
        expires = token['expires_at'].strftime('%Y-%m-%d %H:%M:%S') if token['expires_at'] else 'Never'
        print(f"   Expires:          {expires}")

        if token['expires_at'] and token['expires_at'] < datetime.now():
            print(f"\n   ⚠️  This token is EXPIRED!")

        print("\n" + "="*60 + "\n")

    except Exception as e:
        print(f"\n❌ Error showing token: {e}\n")
        sys.exit(1)


def cmd_revoke(args):
    """Revoke (disable) an API token"""
    manager = create_token_manager()

    try:
        # Confirm
        if not args.yes:
            response = input(f"\n⚠️  Are you sure you want to revoke token ID {args.token_id}? (yes/no): ")
            if response.lower() != 'yes':
                print("Cancelled.")
                return

        manager.revoke_token(args.token_id)
        print(f"\n✅ Token ID {args.token_id} has been revoked.\n")

    except Exception as e:
        print(f"\n❌ Error revoking token: {e}\n")
        sys.exit(1)


def cmd_stats(args):
    """Show token usage statistics"""
    manager = create_token_manager()

    try:
        tokens = manager.list_tokens(include_disabled=False)

        if not tokens:
            print("\nNo active tokens found.\n")
            return

        # Prepare table data
        headers = ["ID", "Name", "Total Req", "Last Hour", "Last 24h", "Errors", "Avg Time (ms)"]
        rows = []

        for token in tokens:
            stats = manager.get_token_stats(token['id'])

            avg_time = stats.get('avg_response_time_ms')
            avg_time_str = f"{avg_time:.1f}" if avg_time else '-'

            rows.append([
                token['id'],
                token['name'][:25],
                stats.get('total_requests', 0),
                stats.get('requests_last_hour', 0),
                stats.get('requests_last_day', 0),
                stats.get('error_count', 0),
                avg_time_str
            ])

        # Sort by total requests descending
        rows.sort(key=lambda x: x[2], reverse=True)

        print("\n" + tabulate(rows, headers=headers, tablefmt='grid'))
        print(f"\nShowing statistics for {len(tokens)} active token(s)\n")

    except Exception as e:
        print(f"\n❌ Error getting stats: {e}\n")
        sys.exit(1)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Manage API tokens for MCP HTTP server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create a read-only token for monitoring
  %(prog)s create --name "Claude Desktop" --scope read_only

  # Create a read-write token with expiration
  %(prog)s create --name "Admin Tool" --scope read_write --expires-days 90

  # List all active tokens
  %(prog)s list

  # Show detailed token info
  %(prog)s show 1

  # Revoke a token
  %(prog)s revoke 3

  # Show usage statistics
  %(prog)s stats

Environment Variables:
  NETMONITOR_DB_HOST      Database host (default: localhost)
  NETMONITOR_DB_PORT      Database port (default: 5432)
  NETMONITOR_DB_NAME      Database name (default: netmonitor)
  NETMONITOR_DB_USER      Database user (default: netmonitor)
  NETMONITOR_DB_PASSWORD  Database password
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Create token
    create_parser = subparsers.add_parser('create', help='Create a new API token')
    create_parser.add_argument('--name', required=True, help='Token name (e.g., "Claude Desktop")')
    create_parser.add_argument('--description', help='Token description')
    create_parser.add_argument('--scope', choices=['read_only', 'read_write', 'admin'],
                              default='read_only', help='Permission scope (default: read_only)')
    create_parser.add_argument('--rate-minute', type=int, default=60,
                              help='Rate limit per minute (default: 60)')
    create_parser.add_argument('--rate-hour', type=int, default=1000,
                              help='Rate limit per hour (default: 1000)')
    create_parser.add_argument('--rate-day', type=int, default=10000,
                              help='Rate limit per day (default: 10000)')
    create_parser.add_argument('--expires-days', type=int,
                              help='Token expires after N days (default: never)')
    create_parser.add_argument('--created-by', help='Creator name')
    create_parser.set_defaults(func=cmd_create)

    # List tokens
    list_parser = subparsers.add_parser('list', help='List all API tokens')
    list_parser.add_argument('--all', action='store_true', help='Include disabled tokens')
    list_parser.set_defaults(func=cmd_list)

    # Show token
    show_parser = subparsers.add_parser('show', help='Show detailed token information')
    show_parser.add_argument('token_id', type=int, help='Token ID')
    show_parser.set_defaults(func=cmd_show)

    # Revoke token
    revoke_parser = subparsers.add_parser('revoke', help='Revoke (disable) an API token')
    revoke_parser.add_argument('token_id', type=int, help='Token ID to revoke')
    revoke_parser.add_argument('-y', '--yes', action='store_true', help='Skip confirmation')
    revoke_parser.set_defaults(func=cmd_revoke)

    # Token stats
    stats_parser = subparsers.add_parser('stats', help='Show token usage statistics')
    stats_parser.set_defaults(func=cmd_stats)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Execute command
    args.func(args)


if __name__ == '__main__':
    main()
