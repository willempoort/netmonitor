#!/usr/bin/env python3
"""
Schema comparison tool - compares database.py definitions with actual database
"""
import psycopg2
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database connection
conn = psycopg2.connect(
    host=os.getenv('DB_HOST', 'localhost'),
    port=os.getenv('DB_PORT', 5432),
    database=os.getenv('DB_NAME', 'netmonitor'),
    user=os.getenv('DB_USER', 'netmonitor'),
    password=os.getenv('DB_PASSWORD', 'netmonitor')
)

cursor = conn.cursor()

# Get all tables
cursor.execute("""
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = 'public'
    AND table_type = 'BASE TABLE'
    ORDER BY table_name;
""")
tables = [row[0] for row in cursor.fetchall()]

print("=" * 80)
print("DATABASE SCHEMA ANALYSIS")
print("=" * 80)
print(f"\nFound {len(tables)} tables in database:\n")

differences_found = False

for table in tables:
    # Get columns for this table
    cursor.execute("""
        SELECT
            column_name,
            data_type,
            character_maximum_length,
            is_nullable,
            column_default
        FROM information_schema.columns
        WHERE table_schema = 'public'
        AND table_name = %s
        ORDER BY ordinal_position;
    """, (table,))

    columns = cursor.fetchall()

    print(f"\n{table.upper()}")
    print("-" * 80)

    for col_name, data_type, max_length, nullable, default in columns:
        type_str = data_type
        if max_length:
            type_str += f"({max_length})"

        null_str = "NULL" if nullable == 'YES' else "NOT NULL"

        default_str = ""
        if default:
            # Shorten long defaults
            default = str(default)
            if len(default) > 50:
                default = default[:47] + "..."
            default_str = f" DEFAULT {default}"

        print(f"  {col_name:30s} {type_str:25s} {null_str:10s}{default_str}")

    # Get indexes for this table
    cursor.execute("""
        SELECT
            indexname,
            indexdef
        FROM pg_indexes
        WHERE schemaname = 'public'
        AND tablename = %s
        ORDER BY indexname;
    """, (table,))

    indexes = cursor.fetchall()
    if indexes:
        print(f"\n  Indexes:")
        for idx_name, idx_def in indexes:
            print(f"    - {idx_name}")

    # Get foreign keys
    cursor.execute("""
        SELECT
            tc.constraint_name,
            kcu.column_name,
            ccu.table_name AS foreign_table_name,
            ccu.column_name AS foreign_column_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
          AND tc.table_schema = kcu.table_schema
        JOIN information_schema.constraint_column_usage AS ccu
          ON ccu.constraint_name = tc.constraint_name
          AND ccu.table_schema = tc.table_schema
        WHERE tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_name = %s;
    """, (table,))

    foreign_keys = cursor.fetchall()
    if foreign_keys:
        print(f"\n  Foreign Keys:")
        for fk_name, col, ref_table, ref_col in foreign_keys:
            print(f"    - {col} -> {ref_table}({ref_col})")

    # Get check constraints
    cursor.execute("""
        SELECT
            constraint_name,
            check_clause
        FROM information_schema.check_constraints
        WHERE constraint_schema = 'public'
        AND constraint_name IN (
            SELECT constraint_name
            FROM information_schema.table_constraints
            WHERE table_name = %s
            AND constraint_type = 'CHECK'
        );
    """, (table,))

    check_constraints = cursor.fetchall()
    if check_constraints:
        print(f"\n  Check Constraints:")
        for cc_name, cc_clause in check_constraints:
            # Shorten long clauses
            if len(cc_clause) > 70:
                cc_clause = cc_clause[:67] + "..."
            print(f"    - {cc_name}: {cc_clause}")

# Check schema version
cursor.execute("SELECT component, version, updated_at FROM schema_version;")
schema_versions = cursor.fetchall()

print("\n\n" + "=" * 80)
print("SCHEMA VERSION INFO")
print("=" * 80)
for component, version, updated_at in schema_versions:
    print(f"{component}: v{version} (updated: {updated_at})")

# Check if TimescaleDB is enabled
cursor.execute("""
    SELECT EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'
    );
""")
timescaledb_enabled = cursor.fetchone()[0]
print(f"\nTimescaleDB extension: {'ENABLED' if timescaledb_enabled else 'DISABLED'}")

if timescaledb_enabled:
    # Check hypertables
    cursor.execute("""
        SELECT hypertable_name, num_dimensions, num_chunks
        FROM timescaledb_information.hypertables
        WHERE hypertable_schema = 'public';
    """)
    hypertables = cursor.fetchall()

    if hypertables:
        print(f"\nHypertables ({len(hypertables)}):")
        for ht_name, num_dims, num_chunks in hypertables:
            print(f"  - {ht_name}: {num_chunks} chunks")

print("\n" + "=" * 80)

conn.close()
