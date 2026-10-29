CREATE TABLE auth_identity_mirrors (
    id UUID PRIMARY KEY,
    provider_id VARCHAR(64) NOT NULL,
    external_subject VARCHAR(256) NOT NULL,
    login VARCHAR(320),
    display_name VARCHAR(256),
    email VARCHAR(320),
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uk_auth_identity_provider_subject UNIQUE (provider_id, external_subject)
);

CREATE TABLE auth_identity_mirror_roles (
    mirror_id UUID NOT NULL,
    role_code VARCHAR(64) NOT NULL,
    CONSTRAINT pk_auth_identity_mirror_roles PRIMARY KEY (mirror_id, role_code),
    CONSTRAINT fk_auth_identity_mirror_roles FOREIGN KEY (mirror_id)
        REFERENCES auth_identity_mirrors (id) ON DELETE CASCADE
);
