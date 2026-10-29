INSERT INTO auth_role_permissions (role_id, permission)
SELECT id, 'auth:audit:read' FROM auth_roles WHERE code = 'AUTH_ADMIN'
ON CONFLICT (role_id, permission) DO NOTHING;
