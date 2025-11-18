# Tenant Management Scripts

This directory contains utility scripts for tenant/organization management.

## Scripts

### `migrations/20240210_add_tenant_app_access_metadata.py`

Adds the new data-plane tracking columns (`network_tier`, `ingress_hostname`, `provisioning_state`, `dns_status`, `provisioning_error`, `last_synced_at`) and the accompanying index to the `tenant_app_access` table.

**Usage:**
```bash
python scripts/migrations/20240210_add_tenant_app_access_metadata.py
```

Run once after deploying the updated service so existing tenants gain the new metadata fields.

### `init_default_apps.py`

Initializes default apps for existing organizations that don't have app access records.

**What it does:**
- Scans all active organizations in the database
- For each organization, checks which default apps are missing from their app catalog
- Adds missing apps with appropriate settings based on the organization's plan:
  - **Trial**: All apps enabled (darkhole, darkfolio, confiploy)
  - **Free**: Only darkhole enabled
  - **Pro**: darkhole and darkfolio enabled
  - **Enterprise**: All apps enabled

**Usage:**
```bash
# From the project root directory
python scripts/init_default_apps.py
```

**When to run:**
- After adding new default apps to the system
- After importing existing organizations that were created before the app system
- After plan migrations that should enable new apps

**Safe to run multiple times:** Yes, the script only adds missing apps and won't duplicate existing ones.

## Default Apps

The system currently has 3 default apps:

1. **DarkHole** (🔮) - AI governance & guard rails
2. **DarkFolio** (📊) - Model cost visibility & analytics
3. **ConfiPloy** (⚙️) - Configuration & rollout management

These are defined in `APP_CATALOG` in `modules/tenant_management.py`.
