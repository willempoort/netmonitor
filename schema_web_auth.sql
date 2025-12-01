-- ============================================
-- Web Authentication Schema
-- User accounts with 2FA support for web dashboard
-- ============================================

-- Web users table with 2FA support
CREATE TABLE IF NOT EXISTS web_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    role VARCHAR(20) DEFAULT 'operator',  -- admin, operator, viewer
    totp_secret VARCHAR(32),  -- Base32 encoded TOTP secret
    totp_enabled BOOLEAN DEFAULT FALSE,
    backup_codes TEXT[],  -- Array of hashed backup codes
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(50),
    CONSTRAINT valid_role CHECK (role IN ('admin', 'operator', 'viewer'))
);

-- Audit log for security events
CREATE TABLE IF NOT EXISTS web_user_audit (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES web_users(id),
    username VARCHAR(50),
    event_type VARCHAR(50) NOT NULL,  -- login, logout, login_failed, 2fa_failed, etc.
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Session management table (optional - Flask-Login uses server-side sessions by default)
CREATE TABLE IF NOT EXISTS web_sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id INTEGER REFERENCES web_users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_activity TIMESTAMPTZ DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMPTZ
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_web_users_username ON web_users(username) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_web_users_email ON web_users(email) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_web_user_audit_user ON web_user_audit(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_web_user_audit_event ON web_user_audit(event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_web_sessions_user ON web_sessions(user_id, last_activity DESC);
CREATE INDEX IF NOT EXISTS idx_web_sessions_expires ON web_sessions(expires_at);

-- Comments for documentation
COMMENT ON TABLE web_users IS 'Web dashboard user accounts with 2FA support';
COMMENT ON TABLE web_user_audit IS 'Audit log for all security-related events';
COMMENT ON TABLE web_sessions IS 'Active user sessions for tracking and management';

COMMENT ON COLUMN web_users.role IS 'User role: admin (full access), operator (manage sensors/alerts), viewer (read-only)';
COMMENT ON COLUMN web_users.totp_secret IS 'Base32-encoded TOTP secret for 2FA (Google Authenticator compatible)';
COMMENT ON COLUMN web_users.backup_codes IS 'Array of Argon2-hashed backup codes for account recovery';
COMMENT ON COLUMN web_users.locked_until IS 'Account locked until this timestamp after failed login attempts';
