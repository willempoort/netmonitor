-- MCP API Tokens Schema
-- DEPRECATED: This file is for reference only!
-- Schema is now managed by database.py _init_mcp_schema() method
-- and is automatically created/updated during NetMonitor startup.
--
-- This file remains as documentation and for manual database recovery only.
-- DO NOT USE THIS FILE IN PRODUCTION SCRIPTS.
--
-- Manages API tokens for HTTP-based MCP server access

-- API Tokens table
CREATE TABLE IF NOT EXISTS mcp_api_tokens (
    id SERIAL PRIMARY KEY,
    token VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Permissions
    scope VARCHAR(50) NOT NULL DEFAULT 'read_only',  -- read_only, read_write, admin
    enabled BOOLEAN NOT NULL DEFAULT true,

    -- Rate limiting
    rate_limit_per_minute INTEGER DEFAULT 60,
    rate_limit_per_hour INTEGER DEFAULT 1000,
    rate_limit_per_day INTEGER DEFAULT 10000,

    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255),
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,

    -- Audit
    request_count BIGINT DEFAULT 0,
    last_ip_address INET,

    -- Constraints
    CONSTRAINT valid_scope CHECK (scope IN ('read_only', 'read_write', 'admin'))
);

-- Token usage log (for audit trail and rate limiting)
CREATE TABLE IF NOT EXISTS mcp_api_token_usage (
    id BIGSERIAL PRIMARY KEY,
    token_id INTEGER REFERENCES mcp_api_tokens(id) ON DELETE CASCADE,

    -- Request details
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,

    -- Client info
    ip_address INET,
    user_agent TEXT,

    -- Response info
    status_code INTEGER,
    response_time_ms INTEGER,
    error_message TEXT
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_mcp_tokens_token ON mcp_api_tokens(token);
CREATE INDEX IF NOT EXISTS idx_mcp_tokens_enabled ON mcp_api_tokens(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_mcp_usage_token_id ON mcp_api_token_usage(token_id);
CREATE INDEX IF NOT EXISTS idx_mcp_usage_timestamp ON mcp_api_token_usage(timestamp);

-- Convert to hypertable for time-series optimization (if TimescaleDB is available)
-- This will automatically partition the usage log by time
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable('mcp_api_token_usage', 'timestamp',
            chunk_time_interval => INTERVAL '7 days',
            if_not_exists => TRUE
        );
    END IF;
END $$;

-- Retention policy: keep usage logs for 90 days
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM add_retention_policy('mcp_api_token_usage',
            INTERVAL '90 days',
            if_not_exists => TRUE
        );
    END IF;
END $$;

-- Comments
COMMENT ON TABLE mcp_api_tokens IS 'API tokens for HTTP-based MCP server authentication';
COMMENT ON TABLE mcp_api_token_usage IS 'Audit log of API token usage for security and rate limiting';
COMMENT ON COLUMN mcp_api_tokens.scope IS 'Permission level: read_only (monitoring only), read_write (can modify config), admin (full access)';
COMMENT ON COLUMN mcp_api_tokens.rate_limit_per_minute IS 'Maximum requests per minute (null = unlimited)';
