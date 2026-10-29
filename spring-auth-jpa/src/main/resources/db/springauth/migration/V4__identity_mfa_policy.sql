-- Local MFA policy is owned by spring-auth, never imported from an external provider.
alter table auth_identity_mirrors
    ADD COLUMN mfa_required BOOLEAN DEFAULT FALSE not null;
