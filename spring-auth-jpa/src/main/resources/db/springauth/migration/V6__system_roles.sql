INSERT INTO auth_roles (id, code, name, description, status, system_role, created_at, updated_at)
VALUES (gen_random_uuid(), 'AUTH_ADMIN', 'spring-auth administrator',
        'User and role administration', 'ACTIVE', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (code) DO NOTHING;

INSERT INTO auth_role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM auth_roles r
CROSS JOIN (VALUES ('auth:users:invite'), ('auth:users:mfa'), ('auth:users:sessions'),
                   ('auth:roles:read'), ('auth:roles:write')) AS p(permission)
WHERE r.code = 'AUTH_ADMIN'
ON CONFLICT (role_id, permission) DO NOTHING;
