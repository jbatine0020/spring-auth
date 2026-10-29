-- PostgreSQL schema: native UUID, boolean, bytea and timezone-aware timestamps.

CREATE TABLE auth_credentials (
    id UUID PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    password_set_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    failed_attempts INTEGER DEFAULT 0 NOT NULL,
    locked_until TIMESTAMP(6) WITH TIME ZONE,
    must_change_password BOOLEAN DEFAULT FALSE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT ck_auth_credentials_failed CHECK (failed_attempts >= 0),
    CONSTRAINT ck_auth_credentials_change CHECK (must_change_password IN (FALSE, TRUE))
);

CREATE TABLE auth_password_history (
    id UUID PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    set_at TIMESTAMP(6) WITH TIME ZONE NOT NULL
);
CREATE INDEX idx_auth_password_history_user_set ON auth_password_history (user_id, set_at DESC);

CREATE TABLE auth_mfa_credentials (
    id UUID PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL UNIQUE,
    encrypted_secret VARCHAR(512) NOT NULL,
    last_accepted_counter BIGINT DEFAULT -1 NOT NULL,
    confirmed_at TIMESTAMP(6) WITH TIME ZONE,
    reset_requested_at TIMESTAMP(6) WITH TIME ZONE,
    failed_attempts INTEGER DEFAULT 0 NOT NULL,
    locked_until TIMESTAMP(6) WITH TIME ZONE,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT ck_auth_mfa_failed CHECK (failed_attempts >= 0)
);

CREATE TABLE auth_refresh_tokens (
    id UUID PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    family_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    issued_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP(6) WITH TIME ZONE,
    replaced_by UUID
);
CREATE INDEX idx_auth_refresh_family ON auth_refresh_tokens (family_id);
CREATE INDEX idx_auth_refresh_user ON auth_refresh_tokens (user_id);
CREATE INDEX idx_auth_refresh_expiry ON auth_refresh_tokens (expires_at);

CREATE TABLE auth_password_resets (
    id UUID PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    otp_hash VARCHAR(255),
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP(6) WITH TIME ZONE,
    failed_attempts INTEGER DEFAULT 0 NOT NULL,
    locked_at TIMESTAMP(6) WITH TIME ZONE,
    requested_by VARCHAR(64),
    CONSTRAINT ck_auth_reset_window CHECK (expires_at > created_at)
);
CREATE INDEX idx_auth_resets_user ON auth_password_resets (user_id);
CREATE INDEX idx_auth_resets_expiry ON auth_password_resets (expires_at);

CREATE TABLE auth_invitations (
    id UUID PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    temporary_password_hash VARCHAR(255),
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    redeemed_at TIMESTAMP(6) WITH TIME ZONE,
    CONSTRAINT ck_auth_invitation_window CHECK (expires_at > created_at)
);
CREATE INDEX idx_auth_invitations_user ON auth_invitations (user_id);
CREATE INDEX idx_auth_invitations_expiry ON auth_invitations (expires_at);

CREATE TABLE auth_login_attempts (
    id UUID PRIMARY KEY,
    user_id VARCHAR(64),
    login VARCHAR(320),
    success_flag BOOLEAN NOT NULL,
    failure_reason VARCHAR(40),
    ip_address VARCHAR(64),
    user_agent VARCHAR(512),
    occurred_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT ck_auth_login_success CHECK (success_flag IN (FALSE, TRUE))
);
CREATE INDEX idx_auth_login_user_time ON auth_login_attempts (user_id, occurred_at DESC);
CREATE INDEX idx_auth_login_time ON auth_login_attempts (occurred_at);

CREATE TABLE auth_roles (
    id UUID PRIMARY KEY,
    code VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(512),
    status VARCHAR(16) NOT NULL,
    system_role BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT ck_auth_roles_system CHECK (system_role IN (FALSE, TRUE))
);

CREATE TABLE auth_role_permissions (
    role_id UUID NOT NULL,
    permission VARCHAR(128) NOT NULL,
    CONSTRAINT pk_auth_role_permissions PRIMARY KEY (role_id, permission),
    CONSTRAINT fk_auth_role_permissions_role FOREIGN KEY (role_id)
        REFERENCES auth_roles (id) ON DELETE CASCADE
);
