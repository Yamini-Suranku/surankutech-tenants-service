"""
Org-scoped Keycloak protocol mappers for app clients.
Used by KeycloakClient.ensure_client_org_mappers.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class ClientConfig:
    client_id: str
    app_name: str
    display_name: str
    create_if_missing: bool


CLIENTS: List[ClientConfig] = [
    ClientConfig(
        client_id="darkhole-client",
        app_name="darkhole",
        display_name="DarkHole",
        create_if_missing=False,
    ),
    ClientConfig(
        client_id="darkfolio-client",
        app_name="darkfolio",
        display_name="DarkFolio",
        create_if_missing=True,
    ),
    ClientConfig(
        client_id="confiploy-client",
        app_name="confiploy",
        display_name="ConfiPloy",
        create_if_missing=True,
    ),
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


def _build_mappers(app_name: str, client_id: str) -> List[dict]:
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


async def _get_client_uuid(client, keycloak, token: str, client_id: str) -> Optional[str]:
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


async def _ensure_client(client, keycloak, token: str, cfg: ClientConfig) -> Optional[str]:
    client_uuid = await _get_client_uuid(client, keycloak, token, cfg.client_id)
    if client_uuid:
        return client_uuid

    if not cfg.create_if_missing:
        return None

    config = _build_client_config(cfg.client_id, cfg.app_name, cfg.display_name)
    create_response = await client.post(
        f"{keycloak.base_url}/admin/realms/{keycloak.realm}/clients",
        headers={"Authorization": f"Bearer {token}"},
        json=config,
    )
    if create_response.status_code != 201:
        raise RuntimeError(f"Failed to create client {cfg.client_id}: {create_response.text}")
    return await _get_client_uuid(client, keycloak, token, cfg.client_id)


async def _apply_mappers(client, keycloak, token: str, client_uuid: str, mappers: List[dict]) -> Dict[str, str]:
    mappers_response = await client.get(
        f"{keycloak.base_url}/admin/realms/{keycloak.realm}/clients/{client_uuid}/protocol-mappers/models",
        headers={"Authorization": f"Bearer {token}"},
    )
    existing = {}
    if mappers_response.status_code == 200:
        for mapper in mappers_response.json():
            existing[mapper["name"]] = mapper

    configured: Dict[str, str] = {}
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
                configured[mapper_name] = mapper_id
        else:
            create_response = await client.post(
                f"{keycloak.base_url}/admin/realms/{keycloak.realm}/clients/{client_uuid}/protocol-mappers/models",
                headers={"Authorization": f"Bearer {token}"},
                json=mapper,
            )
            if create_response.status_code == 201:
                configured[mapper_name] = "created"
    return configured


class ProtocolMappers:
    async def ensure_org_mappers_for_client(self, client_id: str) -> Dict[str, str]:
        from modules.keycloak_client import KeycloakClient
        import httpx

        keycloak = KeycloakClient()
        token = await keycloak.get_admin_token()

        cfg = next((c for c in CLIENTS if c.client_id == client_id), None)
        if cfg is None:
            app_name = client_id.replace("-client", "")
            cfg = ClientConfig(
                client_id=client_id,
                app_name=app_name,
                display_name=app_name.title(),
                create_if_missing=True,
            )

        async with httpx.AsyncClient(timeout=30) as client:
            client_uuid = await _ensure_client(client, keycloak, token, cfg)
            if not client_uuid:
                return {}
            mappers = _build_mappers(cfg.app_name, cfg.client_id)
            return await _apply_mappers(client, keycloak, token, client_uuid, mappers)


protocol_mappers = ProtocolMappers()
