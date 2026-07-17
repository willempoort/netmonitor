# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
NetMonitor version - single source of truth.

Policy (semver, MAJOR.MINOR.PATCH):
- MAJOR: breaking changes (schema/config incompatibilities, removed features)
- MINOR: new functionality, backwards compatible (new detectors, dashboard
  features, API endpoints)
- PATCH: bug fixes only, no new functionality

Bump this file in the same commit as the change, and add an entry to
CHANGELOG.md. Database schema changes are versioned separately via
SCHEMA_VERSION in database.py and don't require an application version bump
by themselves - only bump here if the change is user/operator visible.
"""

__version__ = "2.3.3"
