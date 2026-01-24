#!/usr/bin/env python3
"""
Unified Keycloak mapper setup for org-scoped access across app clients.
Creates/updates clients and applies a consistent mapper set.
"""
import argparse
import asyncio
import os
import sys

sys.path.append(os.path.dirname(__file__))
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from modules.keycloak_client import KeycloakClient


CLIENTS = [
    {
        "client_id": "darkhole-client",
        "app_name": "darkhole",
        "display_name": "DarkHole",
        "create_if_missing": False,
    },
    {
        "client_id": "darkfolio-client",
        "app_name": "darkfolio",
        "display_name": "DarkFolio",
        "create_if_missing": True,
    },
    {
        "client_id": "confiploy-client",
        "app_name": "confiploy",
        "display_name": "ConfiPloy",
        "create_if_missing": True,
    },
]


def _build_client_config(client_id: str, app_name: str, display_name: str) -> dict:
    return {
        "clientId": client_id,
        "name": display_name,
        "description": f"{display_name} application client",
        "enabled": True,
        "clientAuthenticatorType": "client-secret",
        "redirectUris": [
            f"https://*.local.suranku/{app_name}/*",
            f"https://*.{app_name}.suranku.net/*",
            f"http://localhost:*/{app_name}/*",
        ],
        "webOrigins": [
            "https://*.local.suranku",
            f"https://*.{app_name}.suranku.net",
            "http://localhost:*",
        ],
        "protocol": "openid-connect",
        "publicClient": False,
        "bearerOnly": False,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": True,
        "serviceAccountsEnabled": True,
        "authorizationServicesEnabled": False,
        "fullScopeAllowed": True,
    }


def _build_mappers(app_name: str, client_id: str) -> list[dict]:
    return [
        {
            "name": f"{app_name}-org-memberships-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "claim.name": "org_memberships",
                "user.attribute": "org_memberships",
                "jsonType.label": "JSON",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
        {
            "name": f"{app_name}-app-roles-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "claim.name": "app_roles",
                "user.attribute": "app_roles",
                "jsonType.label": "JSON",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
        {
            "name": f"{app_name}-org-app-roles-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "claim.name": "org_app_roles",
                "user.attribute": "org_app_roles",
                "jsonType.label": "JSON",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
        {
            "name": f"{app_name}-groups-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-group-membership-mapper",
            "config": {
                "claim.name": "groups",
                "full.path": "true",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
        {
            "name": f"{app_name}-current-org-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "claim.name": "current_org",
                "user.attribute": "current_org",
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
        {
            "name": f"{app_name}-active-tenant-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "claim.name": "active_tenant",
                "user.attribute": "active_tenant",
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
        {
            "name": f"{app_name}-all-tenants-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "claim.name": "all_tenants",
                "user.attribute": "all_tenants",
                "jsonType.label": "JSON",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
        {
            "name": f"{app_name}-resource-access-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.client.audience": client_id,
                "access.token.claim": "true",
                "id.token.claim": "false",
            },
        },
        {
            "name": f"{app_name}-email-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-property-mapper",
            "config": {
                "claim.name": "email",
                "user.attribute": "email",
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
        {
            "name": f"{app_name}-preferred-username-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-property-mapper",
            "config": {
                "claim.name": "preferred_username",
                "user.attribute": "username",
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
        {
            "name": f"{app_name}-given-name-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-property-mapper",
            "config": {
                "claim.name": "given_name",
                "user.attribute": "firstName",
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
        {
            "name": f"{app_name}-family-name-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-property-mapper",
            "config": {
                "claim.name": "family_name",
                "user.attribute": "lastName",
                "jsonType.label": "String",
                "access.token.claim": "true",
                "id.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        },
    ]


async def _get_client_uuid(client, keycloak: KeycloakClient, token: str, client_id: str) -> str | None:
    response = await client.get(
        f"{keycloak.base_url}/admin/realms/{keycloak.realm}/clients",
        headers={"Authorization": f"Bearer {token}"},
        params={"clientId": client_id},
    )
    if response.status_code != 200:
        raise RuntimeError(f"Failed to get clients for {client_id}: {response.text}")
    clients = response.json()
    if not clients:
        return None
    return clients[0]["id"]


async def _ensure_client(client, keycloak: KeycloakClient, token: str, cfg: dict, dry_run: bool) -> str | None:
    client_id = cfg["client_id"]
    client_uuid = await _get_client_uuid(client, keycloak, token, client_id)
    if client_uuid:
        print(f"[+] Found client {client_id} (UUID: {client_uuid})")
        return client_uuid

    if not cfg.get("create_if_missing"):
        print(f"[!] Client {client_id} missing and create_if_missing=false")
        return None

    if dry_run:
        print(f"[DRY RUN] Would create client {client_id}")
        return None

    config = _build_client_config(client_id, cfg["app_name"], cfg["display_name"])
    create_response = await client.post(
        f"{keycloak.base_url}/admin/realms/{keycloak.realm}/clients",
        headers={"Authorization": f"Bearer {token}"},
        json=config,
    )
    if create_response.status_code != 201:
        raise RuntimeError(f"Failed to create client {client_id}: {create_response.text}")
    client_uuid = await _get_client_uuid(client, keycloak, token, client_id)
    if not client_uuid:
        raise RuntimeError(f"Created client {client_id} but could not fetch UUID")
    print(f"[+] Created client {client_id} (UUID: {client_uuid})")
    return client_uuid


async def _apply_mappers(client, keycloak: KeycloakClient, token: str, client_uuid: str, mappers: list[dict], dry_run: bool) -> None:
    mappers_response = await client.get(
        f"{keycloak.base_url}/admin/realms/{keycloak.realm}/clients/{client_uuid}/protocol-mappers/models",
        headers={"Authorization": f"Bearer {token}"},
    )
    existing = {}
    if mappers_response.status_code == 200:
        for mapper in mappers_response.json():
            existing[mapper["name"]] = mapper

    if dry_run:
        for mapper in mappers:
            action = "Update" if mapper["name"] in existing else "Create"
            print(f"[DRY RUN] {action}: {mapper['name']}")
        return

    success_count = 0
    for mapper in mappers:
        mapper_name = mapper["name"]
        if mapper_name in existing:
            mapper_id = existing[mapper_name]["id"]
            update_response = await client.put(
                f"{keycloak.base_url}/admin/realms/{keycloak.realm}/clients/{client_uuid}/protocol-mappers/models/{mapper_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={**mapper, "id": mapper_id},
            )
            if update_response.status_code in [200, 204]:
                success_count += 1
            else:
                print(f"[-] Failed to update mapper {mapper_name}: {update_response.text}")
        else:
            create_response = await client.post(
                f"{keycloak.base_url}/admin/realms/{keycloak.realm}/clients/{client_uuid}/protocol-mappers/models",
                headers={"Authorization": f"Bearer {token}"},
                json=mapper,
            )
            if create_response.status_code == 201:
                success_count += 1
            else:
                print(f"[-] Failed to create mapper {mapper_name}: {create_response.text}")

    print(f"[+] Mappers configured: {success_count}/{len(mappers)}")


async def setup_unified_org_mappers(dry_run: bool = False) -> bool:
    keycloak = KeycloakClient()
    mode = "DRY RUN" if dry_run else "APPLY"
    print(f"[{mode}] Unified org-scoped mapper setup")
    print("=" * 72)

    token = await keycloak.get_admin_token()

    import httpx

    async with httpx.AsyncClient(timeout=30) as client:
        for cfg in CLIENTS:
            print(f"\n[>] Client: {cfg['client_id']}")
            client_uuid = await _ensure_client(client, keycloak, token, cfg, dry_run)
            if not client_uuid:
                print(f"[!] Skipping mappers for {cfg['client_id']} (no UUID)")
                continue
            mappers = _build_mappers(cfg["app_name"], cfg["client_id"])
            await _apply_mappers(client, keycloak, token, client_uuid, mappers, dry_run)

    print("\nNext steps:")
    print("1) POST /api/token-enhancement/sync-all-users")
    print("2) Users logout/login to refresh tokens")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Setup unified org-scoped Keycloak mappers")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying them")
    args = parser.parse_args()

    success = asyncio.run(setup_unified_org_mappers(dry_run=args.dry_run))
    sys.exit(0 if success else 1)
