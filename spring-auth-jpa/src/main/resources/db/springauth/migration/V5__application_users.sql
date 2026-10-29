CREATE TABLE auth_users (
    id UUID PRIMARY KEY,
    login VARCHAR(320) NOT NULL,
    email VARCHAR(320),
    display_name VARCHAR(256),
    external_subject VARCHAR(256) NOT NULL,
    status VARCHAR(32) NOT NULL,
    mfa_method VARCHAR(20) DEFAULT 'NONE' NOT NULL,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT uk_auth_users_login UNIQUE (login),
    CONSTRAINT uk_auth_users_email UNIQUE (email),
    CONSTRAINT uk_auth_users_subject UNIQUE (external_subject),
    CONSTRAINT ck_auth_users_status CHECK (status IN ('ACTIVE','PENDING_MFA','DISABLED','LOCKED')),
    CONSTRAINT ck_auth_users_mfa CHECK (mfa_method IN ('NONE','TOTP','EMAIL_OTP','SMS_OTP'))
);

CREATE TABLE auth_user_roles (
    user_id UUID NOT NULL,
    role_code VARCHAR(64) NOT NULL,
    CONSTRAINT pk_auth_user_roles PRIMARY KEY (user_id, role_code),
    CONSTRAINT fk_auth_user_roles_user FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
);

INSERT INTO auth_users (id, login, email, display_name, external_subject, status, mfa_method, created_at, updated_at)
SELECT m.id, m.login, m.email, m.display_name, m.external_subject,
       CASE WHEN m.mfa_required = TRUE THEN 'PENDING_MFA' ELSE 'ACTIVE' END,
       CASE WHEN m.mfa_required = TRUE THEN 'TOTP' ELSE 'NONE' END,
       m.created_at, m.updated_at
FROM auth_identity_mirrors m
WHERE EXISTS (SELECT 1 FROM auth_identity_mirror_roles r WHERE r.mirror_id = m.id);

INSERT INTO auth_user_roles (user_id, role_code)
SELECT r.mirror_id, r.role_code
FROM auth_identity_mirror_roles r
WHERE EXISTS (SELECT 1 FROM auth_users u WHERE u.id = r.mirror_id);
