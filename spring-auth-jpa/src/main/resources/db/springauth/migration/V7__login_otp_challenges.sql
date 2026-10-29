CREATE TABLE auth_otp_challenges (
    id UUID PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    channel VARCHAR(8) NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    destination_fingerprint VARCHAR(64) NOT NULL,
    destination_masked VARCHAR(320) NOT NULL,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP(6) WITH TIME ZONE,
    failed_attempts INTEGER DEFAULT 0 NOT NULL,
    locked_at TIMESTAMP(6) WITH TIME ZONE,
    last_sent_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uk_auth_otp_user_channel UNIQUE (user_id, channel),
    CONSTRAINT ck_auth_otp_channel CHECK (channel IN ('EMAIL','SMS')),
    CONSTRAINT ck_auth_otp_attempts CHECK (failed_attempts >= 0)
);

CREATE INDEX ix_auth_otp_expires ON auth_otp_challenges (expires_at);
