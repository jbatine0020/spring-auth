-- Centralized, sanitized audit trail for authentication and application administration.
CREATE TABLE auth_audit_events (
    id UUID PRIMARY KEY,
    audit_reference VARCHAR(64) NOT NULL UNIQUE,
    occurred_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    actor_user_id VARCHAR(64),
    actor_login VARCHAR(320),
    target_user_id VARCHAR(64),
    target_login VARCHAR(320),
    profile_code VARCHAR(64),
    module_name VARCHAR(80) NOT NULL,
    feature_name VARCHAR(120),
    action_name VARCHAR(120) NOT NULL,
    object_reference VARCHAR(320),
    result_code VARCHAR(20) NOT NULL,
    severity_code VARCHAR(20) NOT NULL,
    ip_address VARCHAR(64),
    user_agent VARCHAR(512),
    session_reference VARCHAR(128),
    correlation_id VARCHAR(128),
    details_json TEXT,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT ck_auth_audit_result CHECK (result_code IN ('SUCCESS','FAILURE','DENIED','CANCELLED','ERROR')),
    CONSTRAINT ck_auth_audit_severity CHECK (severity_code IN ('STANDARD','SENSITIVE','CRITICAL'))
);

CREATE INDEX idx_auth_audit_occurred ON auth_audit_events (occurred_at DESC);
CREATE INDEX idx_auth_audit_actor ON auth_audit_events (actor_user_id, occurred_at DESC);
CREATE INDEX idx_auth_audit_target ON auth_audit_events (target_user_id, occurred_at DESC);
CREATE INDEX idx_auth_audit_module ON auth_audit_events (module_name, occurred_at DESC);
CREATE INDEX idx_auth_audit_result ON auth_audit_events (result_code, occurred_at DESC);
