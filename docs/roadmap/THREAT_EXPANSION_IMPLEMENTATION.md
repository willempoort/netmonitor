# Threat Detection Expansion - Implementation Tracking

**Goal:** Expand from 63 → 123 threat types (90%+ coverage in all network-observable categories)

**Branch:** `feature/threat-detection-expansion`

---

## Phase 1 - Quick Wins (LOW effort, HIGH impact)

**Target:** 6 new threats | **Status:** 🚧 IN PROGRESS

| # | Threat Type | Status | Implementation | Config | MCP | UI | Notes |
|---|-------------|--------|----------------|--------|-----|----|----|
| 1 | CRYPTOMINING_POOL | ⬜ TODO | - | - | - | - | Stratum protocol detection |
| 2 | PHISHING_DOMAIN_CONNECTION | ⬜ TODO | - | - | - | - | PhishTank/OpenPhish feeds |
| 3 | TOR_EXIT_NODE | ⬜ TODO | - | - | - | - | Tor exit node IP list |
| 4 | VPN_TUNNEL_DETECTED | ⬜ TODO | - | - | - | - | OpenVPN/WireGuard signatures |
| 5 | CLOUD_METADATA_ACCESS | ⬜ TODO | - | - | - | - | 169.254.169.254 access |
| 6 | SUSPICIOUS_DNS_RATE | ⬜ TODO | - | - | - | - | Abnormal DNS query rate |

### Implementation Checklist per Threat:
- [ ] Detection logic in netmonitor.py
- [ ] Configuration parameter in config.yaml
- [ ] Database schema update (if needed)
- [ ] Web UI toggle in settings
- [ ] MCP API tool (if applicable)
- [ ] Behavior matcher rule (if applicable)
- [ ] Template support (if applicable)
- [ ] Testing with sample traffic
- [ ] Documentation update

---

## Phase 2 - Web Application Layer (MEDIUM effort, HIGH impact)

**Target:** 8 new threats | **Status:** ⬜ NOT STARTED

| # | Threat Type | Status |
|---|-------------|--------|
| 1 | SQL_INJECTION_ATTEMPT | ⬜ TODO |
| 2 | XSS_ATTEMPT | ⬜ TODO |
| 3 | PATH_TRAVERSAL_ATTEMPT | ⬜ TODO |
| 4 | COMMAND_INJECTION_ATTEMPT | ⬜ TODO |
| 5 | XXE_ATTACK | ⬜ TODO |
| 6 | DESERIALIZATION_ATTACK | ⬜ TODO |
| 7 | HTTP_VERB_TAMPERING | ⬜ TODO |
| 8 | HTTP_SMUGGLING | ⬜ TODO |

---

## Phase 3 - DDoS & Resource Exhaustion

**Target:** 8 new threats | **Status:** ⬜ NOT STARTED

---

## Phase 4 - Ransomware Indicators

**Target:** 5 new threats | **Status:** ⬜ NOT STARTED

---

## Phase 5 - IoT & Smart Device Security

**Target:** 8 new threats | **Status:** ⬜ NOT STARTED

---

## Phase 6 - OT/ICS Protocol Security

**Target:** 6 new threats | **Status:** ⬜ NOT STARTED

---

## Phase 7 - Container & Orchestration

**Target:** 4 new threats | **Status:** ⬜ NOT STARTED

---

## Phase 8 - Advanced Evasion

**Target:** 5 new threats | **Status:** ⬜ NOT STARTED

---

## Phase 9 - 90%+ Completion Boost

**Target:** 10 new threats | **Status:** ⬜ NOT STARTED

---

## Configuration Design

All new threats will be configurable via:

```yaml
# config.yaml
detection:
  # Phase 1 - Quick Wins
  cryptomining_detection:
    enabled: true
    stratum_ports: [3333, 4444, 8333, 9999]

  phishing_detection:
    enabled: true
    feed_url: "https://openphish.com/feed.txt"
    update_interval: 3600  # seconds

  tor_detection:
    enabled: true
    exit_node_list_url: "https://check.torproject.org/exit-addresses"

  vpn_detection:
    enabled: true
    detect_openvpn: true
    detect_wireguard: true

  cloud_metadata_detection:
    enabled: true
    aws_metadata: "169.254.169.254"
    azure_metadata: "169.254.169.254"

  dns_anomaly_detection:
    enabled: true
    queries_per_minute_threshold: 100
```

### Web UI Settings Page

New section: **Advanced Threat Detection**

Categories:
- 🔐 Cryptomining & C2
- 🌐 Web Application Security
- 🛡️ DDoS Protection
- 🔒 Ransomware Indicators
- 📱 IoT Security
- 🏭 OT/ICS Security
- 📦 Container Security

Each threat type will have:
- Toggle (enabled/disabled)
- Severity level (INFO/LOW/MEDIUM/HIGH/CRITICAL)
- Threshold parameters (where applicable)
- Per-sensor override capability

---

## MCP API Updates

New MCP tools to add:

1. `get_threat_detection_config` - Get current threat detection configuration
2. `set_threat_detection_config` - Update threat detection settings
3. `get_threat_detection_stats` - Statistics per threat type
4. `test_threat_detection` - Test specific threat detection with sample data

---

## Database Schema Updates

### New table: threat_feeds

```sql
CREATE TABLE threat_feeds (
    id SERIAL PRIMARY KEY,
    feed_type VARCHAR(50) NOT NULL,  -- 'phishing', 'tor_exit', 'cryptomining'
    indicator VARCHAR(255) NOT NULL,  -- IP, domain, hash
    source VARCHAR(100),
    first_seen TIMESTAMP DEFAULT NOW(),
    last_updated TIMESTAMP DEFAULT NOW(),
    metadata JSONB
);

CREATE INDEX idx_threat_feeds_type ON threat_feeds(feed_type);
CREATE INDEX idx_threat_feeds_indicator ON threat_feeds(indicator);
```

---

## Progress Tracking

**Overall Progress:** 0/60 threats implemented (0%)

**Phase 1 Progress:** 0/6 threats (0%)

**Last Updated:** 2026-01-06

---

## Infrastructure Progress

### Completed ✅

1. **Database Schema** - `threat_feeds` table created
   - Supports multiple feed types (phishing, tor_exit, cryptomining, etc.)
   - Indicators: IP, domain, URL, hash, CIDR, ASN
   - Confidence scoring and expiration handling
   - Unique constraint for upsert operations
   - Indexes for fast lookups

2. **Database Methods** - 6 methods added to DatabaseManager
   - `add_threat_feed_indicator()` - Upsert individual indicators
   - `get_threat_feed_indicators()` - Query with filters
   - `check_threat_indicator()` - Exact match lookup
   - `check_ip_in_threat_feeds()` - IP/CIDR matching
   - `cleanup_expired_threat_feeds()` - Mark expired as inactive
   - `bulk_import_threat_feed()` - Bulk import

3. **Configuration Framework** - `config.yaml` extended
   - `thresholds.advanced_threats` section added
   - Phase 1 detections configured (6 types)
   - Per-detection enable toggles
   - Configurable thresholds and feed URLs
   - Update intervals and cache TTL

4. **Threat Feed Updater Service** - Automatic feed updates
   - `ThreatFeedUpdater` class in `threat_feed_updater.py`
   - Phishing feed (OpenPhish) integration
   - Tor exit node feed integration
   - Automatic expiration cleanup
   - Integrated into netmonitor.py as background thread
   - Configurable update intervals

### In Progress 🚧

5. **Detection Logic** - Add detection in packet processing
6. **Web UI Integration** - Advanced Threat Detection settings page
7. **MCP API Tools** - Configuration management endpoints

---

## Testing Strategy

For each threat type:

1. **Unit Tests:** Isolated detection logic
2. **Integration Tests:** Full packet processing pipeline
3. **Sample Traffic:** PCAP files with known threats
4. **False Positive Rate:** Monitor and tune thresholds
5. **Performance Impact:** CPU/RAM usage per sensor

---

## Performance Considerations

- [ ] Implement threat detection toggles for resource-constrained sensors
- [ ] Add configuration presets (minimal, standard, comprehensive)
- [ ] Monitor CPU/RAM usage per detection type
- [ ] Implement batch processing for feed updates
- [ ] Add rate limiting for expensive detections

---

## Rollout Strategy

1. **Phase 1:** Implement on SOC server only, test thoroughly
2. **Phase 2:** Roll out to test sensors with monitoring
3. **Phase 3:** Enable by default for new sensors
4. **Phase 4:** Gradual rollout to production sensors
5. **Phase 5:** Document and announce new capabilities

---

## Notes

- All threat detections must be network-observable (no agents required)
- Focus on IoT/OT scenarios where agents cannot be installed
- Maintain backwards compatibility with existing configurations
- Document all new parameters in USER_MANUAL.md
- Update PITCH_DOCUMENT.md with new capabilities
