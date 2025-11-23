# Platform Admin Setup Guide

This guide explains how to set up and manage platform administrators for the Suranku Platform.

## 🔐 Default Platform Admin Account

When the Keycloak realm is initialized, a default platform admin account is created:

**Default Credentials:**
- **Username:** `platform-admin@suranku.com`
- **Password:** `SurankuAdmin2024!`
- **Roles:** `platform_admin`, `platform-admins`
- **Client Roles:** `darkhole-client/admin`
- **Groups:** `platform-admins`

## ⚠️ Security Warning

**IMPORTANT:** Change the default password immediately after first login!

## 🎯 Platform Admin vs Tenant Admin

### Platform Admin (System-wide)
- **Access Level:** Can view ALL organizations and tenants across the entire SaaS platform
- **Capabilities:**
  - ✅ **Overview only** - monitor system health, view stats
  - ✅ View all organizations and their configurations
  - ✅ Monitor LDAP configurations across tenants
  - ✅ View DNS entries and application status
  - ❌ **Cannot configure** individual organizations
  - ❌ Cannot modify tenant-specific settings
  - ❌ Cannot invite users to specific organizations

### Tenant Admin (Organization-specific)
- **Access Level:** Can fully manage their own organizations
- **Capabilities:**
  - ✅ **Full configuration** for their own organizations
  - ✅ Configure LDAP/AD for their organizations
  - ✅ Invite users and assign app access
  - ✅ Manage DNS settings for their organizations
  - ✅ Create and manage organizations
  - ❌ Cannot see other tenants' organizations

## 🛠 Platform Admin Management

### 1. View Current Admin Information

```bash
cd /path/to/tenants-service
python3 scripts/manage_platform_admin.py info
```

This shows:
- Current default admin credentials
- Assigned roles and groups
- Security warnings

### 2. Change Platform Admin Password

```bash
python3 scripts/manage_platform_admin.py update-password
```

This will:
- Prompt for Keycloak master admin credentials
- Verify the current platform admin user exists
- Allow you to set a new secure password
- Validate password requirements

### 3. Create Additional Platform Admins

```bash
python3 scripts/manage_platform_admin.py create-admin
```

This will:
- Create a new platform admin user with proper roles
- Assign all necessary platform admin permissions
- Add to the platform-admins group

## 🔧 Manual Setup (Advanced)

If you need to manually configure platform admin access:

### 1. Keycloak Roles Required

**Realm Roles:**
- `platform_admin`
- `platform-admins`

**Client Roles:**
- `darkhole-client/admin`

**Groups:**
- `platform-admins`

### 2. Backend Permission Check

The backend checks for platform admin access using:

```python
# In shared/auth.py
def require_platform_admin_access(token_data: TokenData) -> bool:
    # Check platform admin groups
    platform_admin_groups = ["platform-admins", "platform-admin", "admin", "superadmin"]
    user_groups = getattr(token_data, 'groups', [])

    # Check DarkHole admin role
    return require_app_role(token_data, "darkhole", "admin")
```

### 3. Admin Center Access

Platform admins can access the Admin Center at:
- URL: `http://home.local.suranku/dashboard.html`
- Click "Admin Center" in the sidebar
- View: **Platform Admin Center** with overview capabilities

## 🔍 Troubleshooting

### Admin Center Not Visible

If the Admin Center doesn't appear in the dashboard sidebar:

1. **Check Roles:** Verify user has `platform-admins` group and `darkhole-client/admin` role
2. **Check Groups:** User must be in `platform-admins` group
3. **Check Token:** JWT token should include platform admin roles
4. **Check Browser:** Clear browser cache and re-login

### Permission Denied Errors

If getting 403 Forbidden on admin endpoints:

1. **Verify Backend Auth:** Check `/admin/auth-server-info` endpoint access
2. **Check Logs:** Look at tenants-service logs for auth failures
3. **Validate Token:** Use JWT decoder to verify token contains admin roles

### Default Admin Login Issues

If default admin login fails:

1. **Check Keycloak:** Verify user exists in Keycloak admin console
2. **Reset Password:** Use Keycloak admin console to reset password
3. **Check Roles:** Verify all required roles are assigned
4. **Test Connection:** Ensure Keycloak is accessible

## 📋 Deployment Notes

### Initial Deployment

1. **Keycloak Realm:** The realm configuration automatically creates the default admin
2. **Role Assignment:** All necessary roles and groups are pre-configured
3. **First Login:** Use default credentials to access platform admin features

### Production Setup

1. **Change Password:** Immediately change default password
2. **Create Additional Admins:** Set up multiple platform admin accounts
3. **Document Access:** Keep secure record of admin credentials
4. **Regular Rotation:** Implement password rotation policy

## 🔐 Security Best Practices

1. **Strong Passwords:** Use complex passwords with minimum 8 characters
2. **Multiple Admins:** Don't rely on single admin account
3. **Regular Rotation:** Change passwords regularly
4. **Access Logging:** Monitor admin access and activities
5. **Principle of Least Privilege:** Only grant platform admin to those who need it

## 📞 Support

If you need assistance with platform admin setup:

1. Check the logs: `kubectl logs -n tenant-services -l app=tenants-service`
2. Verify Keycloak realm configuration
3. Test admin endpoints directly using curl
4. Review this documentation for troubleshooting steps

---

**Last Updated:** 2025-11-18
**Version:** 1.0
**Author:** Suranku Platform Team