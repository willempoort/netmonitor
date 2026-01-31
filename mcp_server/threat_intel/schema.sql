-- Threat Intelligence Cache Schema
-- Managed by threat_intel_sync.py
-- Caches external threat feeds to reduce API calls and improve response time

-- IP Reputation Cache
CREATE TABLE IF NOT EXISTS threat_intel_ip_cache (
    ip_address INET PRIMARY KEY,

    -- Reputation scores (0-100, higher = more malicious)
    abuseipdb_score INTEGER,
    abuseipdb_reports INTEGER,
    abuseipdb_last_reported TIMESTAMP,

    -- Classification flags
    is_tor_exit BOOLEAN DEFAULT FALSE,
    is_tor_relay BOOLEAN DEFAULT FALSE,
    is_vpn BOOLEAN DEFAULT FALSE,
    is_proxy BOOLEAN DEFAULT FALSE,
    is_datacenter BOOLEAN DEFAULT FALSE,
    is_known_attacker BOOLEAN DEFAULT FALSE,
    is_known_c2 BOOLEAN DEFAULT FALSE,
    is_known_scanner BOOLEAN DEFAULT FALSE,

    -- Tags and categories (JSON array)
    tags JSONB DEFAULT '[]'::jsonb,
    categories JSONB DEFAULT '[]'::jsonb,

    -- Source tracking
    sources JSONB DEFAULT '[]'::jsonb,  -- Which feeds provided this info

    -- Metadata
    first_seen TIMESTAMP DEFAULT NOW(),
    last_updated TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,  -- When to refresh from source

    -- Computed threat level
    threat_level VARCHAR(20) GENERATED ALWAYS AS (
        CASE
            WHEN is_known_c2 OR is_known_attacker THEN 'critical'
            WHEN abuseipdb_score >= 80 OR is_tor_exit THEN 'high'
            WHEN abuseipdb_score >= 50 OR is_known_scanner THEN 'medium'
            WHEN abuseipdb_score >= 20 OR is_vpn OR is_proxy THEN 'low'
            ELSE 'unknown'
        END
    ) STORED
);

-- Feed sync status
CREATE TABLE IF NOT EXISTS threat_intel_feed_status (
    feed_name VARCHAR(100) PRIMARY KEY,
    feed_url TEXT,
    feed_type VARCHAR(50),  -- ip_list, json_api, csv, etc.

    -- Sync status
    last_sync TIMESTAMP,
    last_success TIMESTAMP,
    last_error TEXT,
    records_synced INTEGER DEFAULT 0,

    -- Configuration
    sync_interval_minutes INTEGER DEFAULT 60,
    enabled BOOLEAN DEFAULT TRUE,
    api_key_env_var VARCHAR(100),  -- e.g., 'ABUSEIPDB_API_KEY'

    -- Metadata
    created_at TIMESTAMP DEFAULT NOW()
);

-- Security Knowledge Base
CREATE TABLE IF NOT EXISTS security_knowledge_base (
    id SERIAL PRIMARY KEY,

    -- Categorization
    category VARCHAR(100) NOT NULL,  -- threat_type, mitre_technique, remediation, best_practice
    subcategory VARCHAR(100),

    -- Identifiers
    key VARCHAR(200) NOT NULL,  -- e.g., 'malware.emotet', 'T1566.001', 'brute_force'

    -- Content
    title VARCHAR(500) NOT NULL,
    summary TEXT,
    description TEXT,

    -- Structured data
    indicators JSONB DEFAULT '[]'::jsonb,     -- IOCs, patterns
    recommendations JSONB DEFAULT '[]'::jsonb, -- Action items
    mitre_mapping JSONB DEFAULT '{}'::jsonb,   -- ATT&CK mapping
    reference_links JSONB DEFAULT '[]'::jsonb,  -- External links

    -- Severity/Priority
    severity VARCHAR(20),  -- critical, high, medium, low, info
    priority INTEGER DEFAULT 50,  -- For ordering recommendations

    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    source VARCHAR(200),  -- Where this knowledge came from

    -- Search
    search_vector tsvector GENERATED ALWAYS AS (
        setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('english', coalesce(summary, '')), 'B') ||
        setweight(to_tsvector('english', coalesce(description, '')), 'C')
    ) STORED,

    UNIQUE(category, key)
);

-- Domain reputation cache
CREATE TABLE IF NOT EXISTS threat_intel_domain_cache (
    domain VARCHAR(255) PRIMARY KEY,

    -- Classification
    is_malicious BOOLEAN DEFAULT FALSE,
    is_phishing BOOLEAN DEFAULT FALSE,
    is_malware_host BOOLEAN DEFAULT FALSE,
    is_c2_domain BOOLEAN DEFAULT FALSE,
    is_newly_registered BOOLEAN DEFAULT FALSE,

    -- Reputation
    reputation_score INTEGER,  -- 0-100

    -- Categorization
    categories JSONB DEFAULT '[]'::jsonb,
    tags JSONB DEFAULT '[]'::jsonb,

    -- Metadata
    first_seen TIMESTAMP DEFAULT NOW(),
    last_updated TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    sources JSONB DEFAULT '[]'::jsonb
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_threat_intel_ip_threat_level
    ON threat_intel_ip_cache(threat_level);
CREATE INDEX IF NOT EXISTS idx_threat_intel_ip_tor
    ON threat_intel_ip_cache(is_tor_exit) WHERE is_tor_exit = TRUE;
CREATE INDEX IF NOT EXISTS idx_threat_intel_ip_c2
    ON threat_intel_ip_cache(is_known_c2) WHERE is_known_c2 = TRUE;
CREATE INDEX IF NOT EXISTS idx_threat_intel_ip_expires
    ON threat_intel_ip_cache(expires_at);

CREATE INDEX IF NOT EXISTS idx_security_kb_category
    ON security_knowledge_base(category);
CREATE INDEX IF NOT EXISTS idx_security_kb_key
    ON security_knowledge_base(key);
CREATE INDEX IF NOT EXISTS idx_security_kb_search
    ON security_knowledge_base USING GIN(search_vector);

CREATE INDEX IF NOT EXISTS idx_threat_intel_domain_malicious
    ON threat_intel_domain_cache(is_malicious) WHERE is_malicious = TRUE;

-- Comments
COMMENT ON TABLE threat_intel_ip_cache IS 'Cached IP reputation data from external threat feeds';
COMMENT ON TABLE threat_intel_feed_status IS 'Status and configuration of threat intelligence feeds';
COMMENT ON TABLE security_knowledge_base IS 'Security knowledge for RAG-based recommendations';
COMMENT ON TABLE threat_intel_domain_cache IS 'Cached domain reputation data';
