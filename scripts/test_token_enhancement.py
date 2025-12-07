#!/usr/bin/env python3
"""
Test Token Enhancement Flow
Tests the complete org membership sync and JWT enhancement flow
"""

import asyncio
import json
import sys
import os
from typing import Dict, Any

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from modules.user_attribute_sync import user_attribute_sync
from modules.jwt_token_enhancer import jwt_enhancer
from modules.keycloak_client import KeycloakClient

async def test_user_token_enhancement(user_keycloak_id: str = None, user_email: str = None):
    """Test complete token enhancement flow for a user"""

    print("🧪 Testing Token Enhancement Flow")
    print("=" * 50)

    # Find user if only email provided
    if user_email and not user_keycloak_id:
        from shared.database import get_db_session
        from shared.models import User

        with get_db_session() as db:
            user = db.query(User).filter(User.email == user_email).first()
            if not user:
                print(f"❌ User not found: {user_email}")
                return False
            user_keycloak_id = user.keycloak_id
            if not user_keycloak_id:
                print(f"❌ User {user_email} has no Keycloak ID")
                return False

    if not user_keycloak_id:
        print("❌ Please provide either user_keycloak_id or user_email")
        return False

    print(f"🔍 Testing user: {user_keycloak_id}")

    try:
        # Step 1: Get current org memberships from tenant service
        print("\n📋 Step 1: Getting org memberships from tenant service...")
        org_memberships = await jwt_enhancer.get_user_org_memberships(user_keycloak_id)
        enhanced_data = await jwt_enhancer.get_user_enhanced_token_data(user_keycloak_id)

        print(f"   Found {len(org_memberships)} organization memberships")
        for membership in org_memberships:
            print(f"   - {membership.get('org_name')} ({membership.get('org_slug')})")
            print(f"     Apps: {list(membership.get('app_roles', {}).keys())}")

        # Step 2: Sync attributes to Keycloak
        print("\n🔄 Step 2: Syncing attributes to Keycloak...")
        sync_success = await user_attribute_sync.sync_user_org_memberships(user_keycloak_id)

        if sync_success:
            print("   ✅ Attributes synced successfully")
        else:
            print("   ❌ Attribute sync failed")
            return False

        # Step 3: Verify attributes in Keycloak
        print("\n🔍 Step 3: Verifying attributes in Keycloak...")
        keycloak_client = KeycloakClient()
        user_data = await keycloak_client.get_user_by_id(user_keycloak_id)

        if not user_data:
            print("   ❌ Could not get user from Keycloak")
            return False

        attributes = user_data.get("attributes", {})
        keycloak_org_memberships = []

        if "org_memberships" in attributes:
            try:
                keycloak_org_memberships = json.loads(attributes["org_memberships"][0])
                print(f"   ✅ Found {len(keycloak_org_memberships)} org memberships in Keycloak attributes")
            except (json.JSONDecodeError, IndexError) as e:
                print(f"   ❌ Error parsing org_memberships from Keycloak: {e}")
                return False
        else:
            print("   ⚠️  No org_memberships attribute found in Keycloak")

        # Step 4: Test JWT token (if possible)
        print("\n🎫 Step 4: Testing JWT token generation...")
        try:
            # This would require user credentials, so we'll just verify the setup
            print("   ℹ️  JWT token test requires user credentials")
            print("   ℹ️  The org_memberships should appear in tokens for this user")
        except Exception as e:
            print(f"   ⚠️  Could not test JWT: {e}")

        # Summary
        print("\n📊 Summary:")
        print(f"   Tenant Service Orgs: {len(org_memberships)}")
        print(f"   Keycloak Attributes: {len(keycloak_org_memberships)}")
        print(f"   Enhanced Data Keys: {list(enhanced_data.keys())}")
        print(f"   Sync Status: {'✅ Success' if sync_success else '❌ Failed'}")

        # Show comparison
        tenant_orgs = {m.get('org_slug') for m in org_memberships}
        keycloak_orgs = {m.get('org_slug') for m in keycloak_org_memberships if isinstance(m, dict)}

        if tenant_orgs == keycloak_orgs:
            print("   🎯 Data consistency: PERFECT MATCH")
            return True
        else:
            print(f"   ⚠️  Data mismatch:")
            print(f"      Tenant: {sorted(tenant_orgs)}")
            print(f"      Keycloak: {sorted(keycloak_orgs)}")
            return False

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_sync_api_endpoints():
    """Test the token enhancement API endpoints"""
    print("\n🌐 Testing Token Enhancement API Endpoints")
    print("=" * 50)

    import httpx

    base_url = "http://localhost:8001"  # Adjust if needed

    try:
        async with httpx.AsyncClient() as client:
            # Test health endpoint
            print("🔍 Testing health endpoint...")
            response = await client.get(f"{base_url}/api/token-enhancement/health")
            if response.status_code == 200:
                print("   ✅ Health endpoint working")
            else:
                print(f"   ❌ Health endpoint failed: {response.status_code}")

    except Exception as e:
        print(f"   ⚠️  Could not test API endpoints: {e}")
        print("   ℹ️  Make sure tenant service is running on port 8001")

async def main():
    """Main test function"""

    if len(sys.argv) < 2:
        print("""
🧪 Token Enhancement Test Tool

Usage:
  python test_token_enhancement.py test-user <user_keycloak_id>
  python test_token_enhancement.py test-email <user_email>
  python test_token_enhancement.py test-api
  python test_token_enhancement.py sync-all

Examples:
  python test_token_enhancement.py test-email yamini.sk@suranku.com
  python test_token_enhancement.py test-api
  python test_token_enhancement.py sync-all
        """)
        return 1

    command = sys.argv[1]

    try:
        if command == "test-user":
            if len(sys.argv) < 3:
                print("❌ User Keycloak ID required")
                return 1
            user_keycloak_id = sys.argv[2]
            success = await test_user_token_enhancement(user_keycloak_id=user_keycloak_id)
            return 0 if success else 1

        elif command == "test-email":
            if len(sys.argv) < 3:
                print("❌ User email required")
                return 1
            user_email = sys.argv[2]
            success = await test_user_token_enhancement(user_email=user_email)
            return 0 if success else 1

        elif command == "test-api":
            await test_sync_api_endpoints()
            return 0

        elif command == "sync-all":
            print("🔄 Running bulk sync of all users...")
            result = await user_attribute_sync.sync_all_users_org_memberships()
            print(json.dumps(result, indent=2))
            return 0 if result.get("successful_syncs", 0) > 0 else 1

        else:
            print(f"❌ Unknown command: {command}")
            return 1

    except Exception as e:
        print(f"❌ Command failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)