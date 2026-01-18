#!/usr/bin/env python3
"""
Script to add organization-scoped protocol mappers to existing darkhole-client
Extends the existing setup_client_mappers.py to add org-scoped authentication
"""
import asyncio
import sys
import os
sys.path.append(os.path.dirname(__file__))
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from modules.keycloak_client import KeycloakClient

async def setup_org_scoped_mappers():
    """Add organization-scoped protocol mappers to darkhole-client"""
    try:
        # Initialize Keycloak client
        keycloak = KeycloakClient()

        print("🔥 Setting up Organization-Scoped Protocol Mappers")
        print("=" * 60)

        print("[*] Getting admin token...")
        token = await keycloak.get_admin_token()
        print("[+] Admin token obtained")

        import httpx
        async with httpx.AsyncClient() as client:
            # Target client - reuse existing darkhole-client
            TARGET_CLIENT_ID = "darkhole-client"

            # Get darkhole-client ID
            print(f"[*] Finding {TARGET_CLIENT_ID}...")
            clients_response = await client.get(
                f"{keycloak.base_url}/admin/realms/{keycloak.realm}/clients",
                headers={"Authorization": f"Bearer {token}"},
                params={"clientId": TARGET_CLIENT_ID}
            )

            if clients_response.status_code != 200:
                print(f"[-] Failed to get clients: {clients_response.text}")
                return False

            clients_list = clients_response.json()
            if not clients_list:
                print(f"[-] {TARGET_CLIENT_ID} not found - run setup_keycloak_clients.py first")
                return False

            client_uuid = clients_list[0]["id"]
            print(f"[+] Found {TARGET_CLIENT_ID} (UUID: {client_uuid})")

            # Get existing mappers
            mappers_response = await client.get(
                f"{keycloak.base_url}/admin/realms/{keycloak.realm}/clients/{client_uuid}/protocol-mappers/models",
                headers={"Authorization": f"Bearer {token}"}
            )

            existing_mappers = {}
            if mappers_response.status_code == 200:
                for mapper in mappers_response.json():
                    existing_mappers[mapper["name"]] = mapper
                print(f"[+] Found {len(existing_mappers)} existing mappers")

            # Define organization-scoped mappers to add
            # These extend existing role mappers with organization context
            org_mappers = [
                {
                    "name": "org-memberships-mapper",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "claim.name": "org_memberships",
                        "user.attribute": "org_memberships",
                        "jsonType.label": "JSON",
                        "access.token.claim": "true",
                        "id.token.claim": "true",
                        "userinfo.token.claim": "true"
                    }
                },
                {
                    "name": "enhanced-app-roles-mapper",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "claim.name": "app_roles",
                        "user.attribute": "app_roles",
                        "jsonType.label": "JSON",
                        "access.token.claim": "true",
                        "id.token.claim": "true",
                        "userinfo.token.claim": "true"
                    }
                },
                {
                    "name": "active-tenant-mapper",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "claim.name": "active_tenant",
                        "user.attribute": "active_tenant",
                        "jsonType.label": "String",
                        "access.token.claim": "true",
                        "id.token.claim": "true",
                        "userinfo.token.claim": "true"
                    }
                },
                {
                    "name": "all-tenants-mapper",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "claim.name": "all_tenants",
                        "user.attribute": "all_tenants",
                        "jsonType.label": "JSON",
                        "access.token.claim": "true",
                        "id.token.claim": "true",
                        "userinfo.token.claim": "true"
                    }
                },
                {
                    "name": "current-org-mapper",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "claim.name": "current_org",
                        "user.attribute": "current_org",
                        "jsonType.label": "JSON",
                        "access.token.claim": "true",
                        "id.token.claim": "true",
                        "userinfo.token.claim": "true"
                    }
                }
            ]

            success_count = 0
            for mapper_config in org_mappers:
                mapper_name = mapper_config["name"]

                if mapper_name in existing_mappers:
                    print(f"[*] Mapper '{mapper_name}' already exists, updating...")
                    # Update existing mapper
                    mapper_id = existing_mappers[mapper_name]["id"]
                    update_response = await client.put(
                        f"{keycloak.base_url}/admin/realms/{keycloak.realm}/clients/{client_uuid}/protocol-mappers/models/{mapper_id}",
                        headers={"Authorization": f"Bearer {token}"},
                        json={**mapper_config, "id": mapper_id}
                    )

                    if update_response.status_code in [200, 204]:
                        print(f"[+] Updated mapper '{mapper_name}'")
                        success_count += 1
                    else:
                        print(f"[-] Failed to update mapper '{mapper_name}': {update_response.text}")
                else:
                    print(f"[*] Creating mapper '{mapper_name}'...")
                    create_response = await client.post(
                        f"{keycloak.base_url}/admin/realms/{keycloak.realm}/clients/{client_uuid}/protocol-mappers/models",
                        headers={"Authorization": f"Bearer {token}"},
                        json=mapper_config
                    )

                    if create_response.status_code == 201:
                        print(f"[+] Created mapper '{mapper_name}'")
                        success_count += 1
                    else:
                        print(f"[-] Failed to create mapper '{mapper_name}': {create_response.text}")

            print(f"\n{'='*60}")
            print(f"[+] Organization mappers setup complete! {success_count}/{len(org_mappers)} mappers configured")

            # Test user attribute sync
            print(f"[*] Testing user attribute synchronization...")

            try:
                from modules.user_attribute_sync import user_attribute_sync
                from shared.database import get_db_session
                from shared.models import User

                # Find a test user to sync
                with get_db_session() as db:
                    test_user = db.query(User).filter(User.keycloak_id.isnot(None)).first()
                    if test_user:
                        print(f"[*] Syncing attributes for test user: {test_user.email}")
                        sync_result = await user_attribute_sync.sync_user_org_memberships(test_user.keycloak_id)
                        if sync_result:
                            print(f"[+] User attribute sync successful")
                        else:
                            print(f"[-] User attribute sync failed")
                    else:
                        print(f"[*] No test user found for attribute sync")
            except Exception as e:
                print(f"[!] Could not test attribute sync: {e}")

            print(f"\n💡 Next Steps:")
            print(f"   1. Run user attribute sync for all users:")
            print(f"      POST /api/token-enhancement/sync-all-users")
            print(f"   2. Users must logout and login again for fresh tokens")
            print(f"   3. Test org-scoped access:")
            print(f"      https://palls.darkhole.suranku.net")
            print(f"{'='*60}")
            return True

    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(setup_org_scoped_mappers())
    if success:
        print("\n🎉 Organization-scoped protocol mappers configured!")
        print("🔑 JWT tokens will now include organization membership data")
        exit(0)
    else:
        print("\n💥 Setup failed.")
        exit(1)