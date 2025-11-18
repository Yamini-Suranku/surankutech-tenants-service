#!/usr/bin/env python3
"""
Initialize default apps for existing tenants/organizations that don't have app access records.
This script ensures all organizations have the default apps available in their app catalog.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session
from shared.database import get_db
from shared.models import Tenant, TenantAppAccess
from modules.tenant_management import (
    APP_CATALOG,
    get_trial_features,
    get_app_features,
    get_app_user_limit,
    seed_app_access_metadata
)

def init_default_apps_for_tenant(db: Session, tenant: Tenant):
    """Initialize default apps for a specific tenant"""
    print(f"Processing tenant: {tenant.name} (ID: {tenant.id})")

    # Get existing app access records for this tenant
    existing_apps = set(
        record.app_name for record in
        db.query(TenantAppAccess).filter(TenantAppAccess.tenant_id == tenant.id).all()
    )

    apps_added = 0
    for app_name in APP_CATALOG.keys():
        if app_name not in existing_apps:
            print(f"  Adding app access for: {app_name}")

            # Determine if app should be enabled based on plan
            is_enabled = False
            if tenant.plan_id == "trial":
                # Enable all apps for trial tenants
                is_enabled = True
            elif tenant.plan_id == "free" and app_name == "darkhole":
                # Only enable darkhole for free plan
                is_enabled = True
            elif tenant.plan_id in ["pro", "enterprise"]:
                # Enable based on plan availability
                if app_name in ["darkhole", "darkfolio"]:
                    is_enabled = True
                elif tenant.plan_id == "enterprise" and app_name == "confiploy":
                    is_enabled = True

            # Create app access record
            app_access = TenantAppAccess(
                tenant_id=tenant.id,
                app_name=app_name,
                is_enabled=is_enabled,
                user_limit=get_app_user_limit(app_name, tenant.plan_id),
                current_users=1 if is_enabled else 0,
                enabled_features=get_app_features(app_name, tenant.plan_id)
            )
            seed_app_access_metadata(app_access, tenant, app_name)
            db.add(app_access)
            apps_added += 1

    if apps_added > 0:
        print(f"  Added {apps_added} app(s)")
        return apps_added
    else:
        print(f"  No apps to add (already has all default apps)")
        return 0

def main():
    """Initialize default apps for all existing tenants"""
    print("Initializing default apps for existing organizations...")

    # Get database session
    db = next(get_db())

    try:
        # Get all active tenants
        active_tenants = db.query(Tenant).filter(Tenant.is_active == True).all()

        print(f"Found {len(active_tenants)} active organizations")

        total_apps_added = 0
        tenants_updated = 0

        for tenant in active_tenants:
            apps_added = init_default_apps_for_tenant(db, tenant)
            if apps_added > 0:
                tenants_updated += 1
                total_apps_added += apps_added

        # Commit all changes
        db.commit()

        print(f"\n✅ Initialization complete!")
        print(f"   Organizations updated: {tenants_updated}")
        print(f"   Total apps added: {total_apps_added}")

        if tenants_updated == 0:
            print("   All organizations already have default apps configured")

    except Exception as e:
        print(f"❌ Error during initialization: {e}")
        db.rollback()
        sys.exit(1)

    finally:
        db.close()

if __name__ == "__main__":
    main()
