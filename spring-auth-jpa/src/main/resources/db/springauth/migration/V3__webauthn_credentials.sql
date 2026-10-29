-- WebAuthn credentials are opaque public-key records; private keys never reach spring-auth.
create table auth_webauthn_credentials (
    credential_id VARCHAR(512) not null,
    user_id VARCHAR(64) not null,
    public_key BYTEA not null,
    signature_counter BIGINT default 0 not null,
    display_name VARCHAR(160),
    created_at timestamp(6) with time zone not null,
    last_used_at timestamp(6) with time zone,
    constraint pk_auth_webauthn_credentials primary key (credential_id)
);

create index ix_auth_webauthn_user on auth_webauthn_credentials (user_id);
