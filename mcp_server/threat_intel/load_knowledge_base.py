#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025
"""
Load Security Knowledge Base into PostgreSQL

Loads the knowledge_base.json file into the security_knowledge_base table
for use in RAG-based threat analysis and recommendations.

Usage:
    python load_knowledge_base.py
    python load_knowledge_base.py --reload  # Clear and reload
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime

import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('KnowledgeBaseLoader')

load_dotenv()


def get_connection():
    return psycopg2.connect(
        host=os.environ.get('DB_HOST', 'localhost'),
        database=os.environ.get('DB_NAME', 'netmonitor'),
        user=os.environ.get('DB_USER', 'netmonitor'),
        password=os.environ.get('DB_PASSWORD', 'netmonitor'),
    )


def load_knowledge_base(reload: bool = False):
    """Load knowledge base from JSON file into database"""
    kb_path = Path(__file__).parent / 'knowledge_base.json'
    if not kb_path.exists():
        logger.error(f"Knowledge base not found: {kb_path}")
        return False

    with open(kb_path) as f:
        kb_data = json.load(f)

    conn = get_connection()
    try:
        cursor = conn.cursor()

        # Initialize schema first
        schema_path = Path(__file__).parent / 'schema.sql'
        if schema_path.exists():
            cursor.execute(schema_path.read_text())
            conn.commit()

        if reload:
            cursor.execute('DELETE FROM security_knowledge_base')
            logger.info("Cleared existing knowledge base entries")

        records = []
        now = datetime.now()

        # Load threat types
        for key, data in kb_data.get('threat_types', {}).items():
            records.append({
                'category': 'threat_type',
                'subcategory': None,
                'key': key,
                'title': data.get('title', key),
                'summary': data.get('description', ''),
                'description': data.get('description', ''),
                'indicators': json.dumps(data.get('indicators', [])),
                'recommendations': json.dumps(data.get('recommendations', [])),
                'mitre_mapping': json.dumps({'techniques': data.get('mitre', [])}),
                'reference_links': json.dumps([]),
                'severity': data.get('severity', 'medium'),
                'priority': _severity_to_priority(data.get('severity', 'medium')),
                'source': 'knowledge_base.json',
                'created_at': now,
                'updated_at': now,
            })

        # Load network anomalies
        for key, data in kb_data.get('network_anomalies', {}).items():
            records.append({
                'category': 'network_anomaly',
                'subcategory': None,
                'key': key,
                'title': data.get('title', key),
                'summary': data.get('description', ''),
                'description': data.get('description', ''),
                'indicators': json.dumps([]),
                'recommendations': json.dumps(data.get('recommendations', [])),
                'mitre_mapping': json.dumps({}),
                'reference_links': json.dumps([]),
                'severity': data.get('severity', 'info'),
                'priority': _severity_to_priority(data.get('severity', 'info')),
                'source': 'knowledge_base.json',
                'created_at': now,
                'updated_at': now,
            })

        # Load IP reputation info
        for key, data in kb_data.get('ip_reputation', {}).items():
            records.append({
                'category': 'ip_reputation',
                'subcategory': None,
                'key': key,
                'title': data.get('title', key),
                'summary': data.get('description', ''),
                'description': data.get('description', ''),
                'indicators': json.dumps([]),
                'recommendations': json.dumps(data.get('recommendations', [])),
                'mitre_mapping': json.dumps({}),
                'reference_links': json.dumps([]),
                'severity': data.get('severity', 'info'),
                'priority': _severity_to_priority(data.get('severity', 'info')),
                'source': 'knowledge_base.json',
                'created_at': now,
                'updated_at': now,
            })

        # Load general recommendations
        for key, items in kb_data.get('general_recommendations', {}).items():
            records.append({
                'category': 'general_recommendation',
                'subcategory': None,
                'key': key,
                'title': key.replace('_', ' ').title(),
                'summary': f"Algemene aanbevelingen voor {key.replace('_', ' ')}",
                'description': '',
                'indicators': json.dumps([]),
                'recommendations': json.dumps(items),
                'mitre_mapping': json.dumps({}),
                'reference_links': json.dumps([]),
                'severity': 'info',
                'priority': 50,
                'source': 'knowledge_base.json',
                'created_at': now,
                'updated_at': now,
            })

        # Insert records
        columns = list(records[0].keys())
        values = [[r[col] for col in columns] for r in records]

        insert_sql = f'''
            INSERT INTO security_knowledge_base ({', '.join(columns)})
            VALUES %s
            ON CONFLICT (category, key) DO UPDATE SET
                title = EXCLUDED.title,
                summary = EXCLUDED.summary,
                description = EXCLUDED.description,
                indicators = EXCLUDED.indicators,
                recommendations = EXCLUDED.recommendations,
                mitre_mapping = EXCLUDED.mitre_mapping,
                severity = EXCLUDED.severity,
                priority = EXCLUDED.priority,
                updated_at = EXCLUDED.updated_at
        '''

        execute_values(cursor, insert_sql, values)
        conn.commit()

        logger.info(f"Loaded {len(records)} knowledge base entries")
        return True

    except Exception as e:
        logger.error(f"Error loading knowledge base: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


def _severity_to_priority(severity: str) -> int:
    """Convert severity to numeric priority (lower = higher priority)"""
    mapping = {
        'critical': 10,
        'high': 20,
        'medium': 50,
        'low': 70,
        'info': 90,
    }
    return mapping.get(severity.lower(), 50)


def main():
    parser = argparse.ArgumentParser(description='Load Security Knowledge Base')
    parser.add_argument('--reload', action='store_true', help='Clear and reload all entries')
    args = parser.parse_args()

    success = load_knowledge_base(reload=args.reload)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
