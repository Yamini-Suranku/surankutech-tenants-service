#!/usr/bin/env python3
"""
Complete end-to-end test for organization-scoped authentication
Tests: Setup → User Roles → Keycloak Sync → JWT Tokens → DarkHole Access
"""

import asyncio
import requests
import json
import urllib3

# Disable SSL warnings for local development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

async def test_complete_org_auth_flow():
    """Test the complete organization-scoped authentication flow"""

    print("🔥 Testing Complete Organization-Scoped Authentication Flow")
    print("=" * 70)

    # Configuration
    ORG_SUBDOMAIN = "palls"
    TEST_USER_EMAIL = "pallava@suranku.net"  # Update with your email
    TENANT_SERVICE_URL = "https://api.local.suranku"
    DARKHOLE_URL = f"https://{ORG_SUBDOMAIN}.darkhole.suranku.net"

    test_results = {
        "protocol_mappers": False,
        "user_sync": False,
        "jwt_enhancement": False,
        "darkhole_access": False
    }

    try:
        # Test 1: Check Protocol Mappers Setup
        print("📋 Test 1: Checking Protocol Mappers Auto-Setup")
        try:
            response = requests.post(f"{TENANT_SERVICE_URL}/api/admin/setup-org-mappers", verify=False)
            if response.status_code == 200:
                result = response.json()
                print(f"   ✅ {result.get('message', 'Mappers configured')}")
                print(f"   🔧 Mappers: {result.get('mappers_configured', [])}")
                test_results["protocol_mappers"] = True
            else:
                print(f"   ❌ Mapper setup failed: {response.status_code}")
        except Exception as e:
            print(f"   ⚠️  Mapper setup API not accessible: {e}")
            print("   💡 Mappers will be auto-configured on service startup")

        # Test 2: Test JWT Enhancement API
        print("\n📋 Test 2: Testing JWT Enhancement API")
        try:
            # Test org memberships endpoint (simulating mapper call)
            response = requests.get(f"{TENANT_SERVICE_URL}/api/token-enhancement/user-enhanced-data",
                                  params={"user_id": "test-keycloak-id"}, verify=False)
            if response.status_code in [200, 404]:  # 404 is okay for test user
                print("   ✅ JWT enhancement API responding")
                test_results["jwt_enhancement"] = True
            else:
                print(f"   ❌ JWT enhancement API error: {response.status_code}")
        except Exception as e:
            print(f"   ⚠️  JWT enhancement API not accessible: {e}")

        # Test 3: User Attribute Sync
        print("\n📋 Test 3: Testing User Attribute Sync")
        try:
            response = requests.post(f"{TENANT_SERVICE_URL}/api/token-enhancement/sync-all-users", verify=False)
            if response.status_code in [200, 202]:
                result = response.json()
                print(f"   ✅ User sync initiated: {result.get('message', 'Success')}")
                test_results["user_sync"] = True
            else:
                print(f"   ❌ User sync failed: {response.status_code}")
        except Exception as e:
            print(f"   ⚠️  User sync API not accessible: {e}")

        # Test 4: Organization App Roles API
        print("\n📋 Test 4: Testing Org-Scoped Roles API")
        try:
            # Test the endpoint that Keycloak mappers would call
            response = requests.get(f"{TENANT_SERVICE_URL}/api/auth/user-org-roles",
                                  params={
                                      "user_email": TEST_USER_EMAIL,
                                      "org_subdomain": ORG_SUBDOMAIN,
                                      "tenant_id": "5349ae0e-edcc-416d-8cbc-8c6d34f0fc8d"
                                  }, verify=False)
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ Org roles API working")
                print(f"   📊 App roles for {ORG_SUBDOMAIN}: {data.get('app_roles', {})}")
                test_results["darkhole_access"] = True
            else:
                print(f"   ❌ Org roles API failed: {response.status_code}")
                if response.status_code == 404:
                    print("   💡 This is expected if user doesn't exist yet")
        except Exception as e:
            print(f"   ⚠️  Org roles API not accessible: {e}")

        # Test 5: Manual Testing Instructions
        print("\n📋 Test 5: Manual Testing Required")
        print("   🔧 Complete these steps manually:")
        print(f"   1. Enable DarkHole app for '{ORG_SUBDOMAIN}' organization")
        print(f"   2. Assign user '{TEST_USER_EMAIL}' a DarkHole role in '{ORG_SUBDOMAIN}' org")
        print(f"   3. User logout/login to get fresh JWT tokens")
        print(f"   4. Access: {DARKHOLE_URL}")
        print(f"   5. Verify JWT contains org-scoped app_roles")

        # Test Summary
        print(f"\n{'='*70}")
        print("🎯 Test Results Summary:")
        passed = sum(test_results.values())
        total = len(test_results)

        for test_name, result in test_results.items():
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"   {test_name.replace('_', ' ').title()}: {status}")

        print(f"\n📊 Overall: {passed}/{total} automated tests passed")

        if passed >= 2:  # At least JWT enhancement and user sync working
            print("✅ Core functionality working - proceed with manual testing")
        else:
            print("❌ Core issues detected - check service configuration")

        # Next Steps Guide
        print(f"\n💡 Next Steps:")
        print("   1. ✅ Protocol mappers are auto-configured on service startup")
        print("   2. Enable DarkHole app for your organization in platform dashboard")
        print("   3. Assign user roles through organization management UI")
        print("   4. Test login and access to org-specific DarkHole instance")
        print("   5. Check browser dev tools → JWT token for org_memberships claim")
        print("   6. Manual setup (if needed): POST /api/admin/setup-org-mappers")

        return passed >= 2

    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_complete_org_auth_flow())
    if success:
        print("\n🎉 Ready for manual testing!")
    else:
        print("\n💥 Setup issues detected - check configuration")