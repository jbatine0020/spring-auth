ALTER TABLE auth_users
    ADD COLUMN phone_number VARCHAR(32),
    ADD COLUMN phone_verified_at TIMESTAMP(6) WITH TIME ZONE,
    ADD COLUMN email_verified_at TIMESTAMP(6) WITH TIME ZONE;

CREATE INDEX ix_auth_users_phone ON auth_users (phone_number);
