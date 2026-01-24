# Keycloak Mapper Implementation for DarkFolio and ConfiPloy

## Overview

The `setup_unified_org_mappers.py` script creates/updates Keycloak clients and protocol mappers for `darkfolio-client` and `confiploy-client` to enable organization-scoped authentication.

## What Gets Implemented

### 1. New Keycloak Clients Created

#### DarkFolio Client (`darkfolio-client`)
```json
{
  "clientId": "darkfolio-client",
  "name": "DarkFolio",
  "description": "DarkFolio application client",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "redirectUris": [
    "https://*.local.suranku/darkfolio/*",
    "https://*.darkfolio.suranku.net/*",
    "http://localhost:*/darkfolio/*"
  ],
  "webOrigins": [
    "https://*.local.suranku",
    "https://*.darkfolio.suranku.net",
    "http://localhost:*"
  ],
  "protocol": "openid-connect",
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "serviceAccountsEnabled": true
}
```

#### ConfiPloy Client (`confiploy-client`)
```json
{
  "clientId": "confiploy-client",
  "name": "ConfiPloy",
  "description": "ConfiPloy application client",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "redirectUris": [
    "https://*.local.suranku/confiploy/*",
    "https://*.confiploy.suranku.net/*",
    "http://localhost:*/confiploy/*"
  ],
  "webOrigins": [
    "https://*.local.suranku",
    "https://*.confiploy.suranku.net",
    "http://localhost:*"
  ],
  "protocol": "openid-connect",
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "serviceAccountsEnabled": true
}
```

### 2. Protocol Mappers Added (for each client)

#### Organization Membership Mappers

1. **Org Memberships Mapper**
   - **Name**: `{app_name}-org-memberships-mapper`
   - **Type**: `oidc-usermodel-attribute-mapper`
   - **Claim**: `org_memberships`
   - **User Attribute**: `org_memberships`
   - **JSON Type**: String
   - **Included in**: Access token, ID token, UserInfo

2. **App Roles Mapper**
   - **Name**: `{app_name}-app-roles-mapper`
   - **Type**: `oidc-usermodel-attribute-mapper`
   - **Claim**: `app_roles`
   - **User Attribute**: `app_roles`
   - **JSON Type**: JSON
   - **Included in**: Access token, ID token, UserInfo

3. **Org App Roles Mapper**
   - **Name**: `{app_name}-org-app-roles-mapper`
   - **Type**: `oidc-usermodel-attribute-mapper`
   - **Claim**: `org_app_roles`
   - **User Attribute**: `org_app_roles`
   - **JSON Type**: JSON
   - **Included in**: Access token, ID token, UserInfo

4. **Groups Mapper**
   - **Name**: `{app_name}-groups-mapper`
   - **Type**: `oidc-group-membership-mapper`
   - **Claim**: `groups`
   - **Full Path**: true
   - **Included in**: Access token, ID token, UserInfo

5. **Current Org Mapper**
   - **Name**: `{app_name}-current-org-mapper`
   - **Type**: `oidc-usermodel-attribute-mapper`
   - **Claim**: `current_org`
   - **User Attribute**: `current_org`
   - **JSON Type**: JSON
   - **Included in**: Access token, ID token, UserInfo

6. **Resource Access Mapper**
   - **Name**: `{app_name}-resource-access-mapper`
   - **Type**: `oidc-audience-mapper`
   - **Included Client Audience**: `{client_id}`
   - **Included in**: Access token only

#### Standard OIDC Mappers

7. **Email Mapper**
   - **Name**: `{app_name}-email-mapper`
   - **Type**: `oidc-usermodel-property-mapper`
   - **Claim**: `email`
   - **User Attribute**: `email`

8. **Preferred Username Mapper**
   - **Name**: `{app_name}-preferred-username-mapper`
   - **Type**: `oidc-usermodel-property-mapper`
   - **Claim**: `preferred_username`
   - **User Attribute**: `username`

9. **Given Name Mapper**
   - **Name**: `{app_name}-given-name-mapper`
   - **Type**: `oidc-usermodel-property-mapper`
   - **Claim**: `given_name`
   - **User Attribute**: `firstName`

10. **Family Name Mapper**
    - **Name**: `{app_name}-family-name-mapper`
    - **Type**: `oidc-usermodel-property-mapper`
    - **Claim**: `family_name`
    - **User Attribute**: `lastName`

## How It Integrates with the Platform

### Token Enhancement Flow

1. **User Management**: Platform UI creates orgs and assigns roles via `suranku-api` client
2. **Token Creation**: When user logs into darkfolio/confiploy, their client's mappers trigger
3. **Data Source**: Mappers pull org membership data from user attributes populated by tenant service
4. **Token Content**: JWT includes org-scoped role information for the specific application

#### Attribute Sources (Keycloak User Attributes)

- **org_memberships**: written by the tenant service bulk sync (`/api/token-enhancement/sync-all-users`) from `OrganizationUserRole` + tenant roles.
- **app_roles**: written by the tenant service bulk sync (consolidated app roles across tenants).
- **org_app_roles**: derived during token-enhancement sync from `OrganizationUserRole` + `OrganizationAppAccess` (flattened `{ org_slug, app, roles }`), then stored as a Keycloak user attribute.
- **current_org**: set during token-enhancement sync from the user’s active org context (prefers an explicitly active org when present, otherwise first org in `org_memberships`) and stored as a Keycloak user attribute.

### Example JWT Token Structure

```json
{
  "sub": "keycloak-user-id",
  "preferred_username": "user@example.com",
  "email": "user@example.com",
  "given_name": "John",
  "family_name": "Doe",
  "org_memberships": [
    {
      "tenant_id": "tenant-uuid",
      "org_id": "org-uuid",
      "org_slug": "acme-corp",
      "org_name": "ACME Corporation",
      "app_roles": {
        "darkfolio": ["admin", "user"],
        "confiploy": ["user"]
      }
    }
  ],
  "groups": ["/orgs/acme-corp/darkfolio/admin"],
  "current_org": "acme-corp",
  "app_roles": {
    "darkfolio": ["admin", "user"]
  },
  "org_app_roles": [
    {
      "org_slug": "acme-corp",
      "app": "darkfolio",
      "roles": ["admin", "user"]
    }
  ],
  "aud": ["darkfolio-client"]
}
```

## Usage Instructions

### To Run the Implementation

```bash
# Preview what will be created (safe)
python3 scripts/setup_unified_org_mappers.py --dry-run

# Apply the changes (requires Keycloak running)
python3 scripts/setup_unified_org_mappers.py
```

### Requirements

1. Keycloak instance running at `keycloak.local.suranku`
2. Valid admin credentials in environment variables
3. `suranku-platform` realm exists
4. Tenant service running for token enhancement API

### Post-Implementation Steps

1. **User Attribute Sync**: Run user attribute sync to populate org membership data
   ```bash
   POST /api/token-enhancement/sync-all-users
   ```

2. **Test Token Generation**: Users must logout and login again to get fresh tokens

3. **Verify App Access**: Test access to applications
   - https://ibaiss.local.suranku/darkfolio/
   - https://ibaiss.local.suranku/confiploy/

## Security Benefits

1. **App Isolation**: Each app has its own Keycloak client with specific configuration
2. **Org Scoping**: Tokens include only relevant organization data based on URL context
3. **Role Granularity**: Fine-grained app-specific roles per organization
4. **Centralized Management**: All user/org management through platform UI
5. **Real-time Updates**: Token enhancement ensures fresh role data on each login

## Troubleshooting

- **Missing Claims**: Check if user attribute sync has been run
- **Wrong Organization**: Verify URL subdomain matches org slug
- **Access Denied**: Confirm user has appropriate app role for the organization
- **Token Issues**: Check Keycloak logs for mapper execution errors
