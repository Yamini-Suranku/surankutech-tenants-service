#!/usr/bin/env python3
"""
Token Generation Script for Testing Organization Management Endpoints

This script generates authentication tokens for testing the tenants service APIs
through Kong Gateway.
"""

import requests
import json
import sys
from typing import Optional

# Default configuration
DEFAULT_API_BASE = "http://api.local.suranku"
DEFAULT_EMAIL = "yamini.sk@suranku.com"
DEFAULT_PASSWORD = "Time2show@25"

def get_auth_token(email: str = DEFAULT_EMAIL, password: str = DEFAULT_PASSWORD,
                   api_base: str = DEFAULT_API_BASE, verify_tls: bool = True) -> Optional[str]:
    """
    Get authentication token from the tenants service.

    Args:
        email: User email address
        password: User password
        api_base: Base API URL (e.g., http://api.local.suranku)

    Returns:
        Authentication token string or None if failed
    """
    login_url = f"{api_base}/api/auth/login"

    payload = {
        "email": email,
        "password": password
    }

    headers = {
        "Content-Type": "application/json"
    }

    try:
        print(f"🔐 Authenticating with {email}...")
        response = requests.post(
            login_url,
            json=payload,
            headers=headers,
            timeout=10,
            verify=verify_tls
        )

        if response.status_code == 200:
            data = response.json()
            token = data.get('access_token')
            user_info = data.get('user', {})
            tenants = data.get('tenants', [])

            print(f"✅ Authentication successful!")
            print(f"👤 User: {user_info.get('first_name', '')} {user_info.get('last_name', '')}")
            print(f"📧 Email: {user_info.get('email', '')}")
            print(f"🏢 Tenants: {len(tenants)} available")

            if tenants:
                current_tenant = data.get('current_tenant', {})
                print(f"🎯 Current tenant: {current_tenant.get('name', 'N/A')} ({current_tenant.get('id', 'N/A')})")

            return token
        else:
            print(f"❌ Authentication failed: {response.status_code}")
            try:
                error_data = response.json()
                print(f"   Error: {error_data.get('detail', 'Unknown error')}")
            except:
                print(f"   Response: {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"❌ Connection error: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None

def test_organization_endpoints(token: str, tenant_id: str, api_base: str = DEFAULT_API_BASE, verify_tls: bool = True):
    """
    Test organization management endpoints with the provided token.

    Args:
        token: Authentication token
        tenant_id: Tenant ID to test with
        api_base: Base API URL
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    print(f"\n🧪 Testing organization endpoints for tenant: {tenant_id}")

    # Test organization list
    print("📋 Testing organization list...")
    try:
        response = requests.get(f"{api_base}/api/tenants/{tenant_id}/organizations",
                              headers=headers, timeout=10, verify=verify_tls)
        if response.status_code == 200:
            orgs = response.json().get('organizations', [])
            print(f"   ✅ Found {len(orgs)} organizations")
            for org in orgs:
                print(f"      - {org.get('name')} (ID: {org.get('id')})")
        else:
            print(f"   ❌ Failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")

    # Test organization apps
    print("📱 Testing organization apps...")
    try:
        response = requests.get(f"{api_base}/api/tenants/{tenant_id}/organizations/default/apps",
                              headers=headers, timeout=10, verify=verify_tls)
        if response.status_code == 200:
            data = response.json()
            available = data.get('available_apps', [])
            enabled = data.get('enabled_apps', [])
            print(f"   ✅ Found {len(available)} available apps, {len(enabled)} enabled")
            for app in enabled:
                print(f"      - {app.get('name')} ({app.get('category')})")
        else:
            print(f"   ❌ Failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Error: {e}")

def main():
    """Main function to generate token and optionally test endpoints."""
    import argparse

    parser = argparse.ArgumentParser(description='Generate authentication token for testing')
    parser.add_argument('--email', default=DEFAULT_EMAIL, help='Email address')
    parser.add_argument('--password', default=DEFAULT_PASSWORD, help='Password')
    parser.add_argument('--api-base', default=DEFAULT_API_BASE, help='Base API URL')
    parser.add_argument('--insecure', action='store_true',
                        help='Disable TLS verification (use for local certs)')
    parser.add_argument('--test', action='store_true', help='Test organization endpoints')
    parser.add_argument('--tenant-id', help='Tenant ID for testing (required with --test)')
    parser.add_argument('--output', choices=['token', 'json', 'export'], default='token',
                       help='Output format: token only, full JSON, or shell export')

    args = parser.parse_args()

    # Get token
    verify_tls = not args.insecure
    token = get_auth_token(args.email, args.password, args.api_base, verify_tls=verify_tls)

    if not token:
        print("❌ Failed to get authentication token")
        sys.exit(1)

    # Output token in requested format
    if args.output == 'token':
        print(f"\n🎫 Token: {token}")
    elif args.output == 'json':
        print(f"\n🎫 Token JSON:")
        print(json.dumps({"access_token": token}, indent=2))
    elif args.output == 'export':
        print(f"\n🎫 Shell export:")
        print(f"export TOKEN='{token}'")
        print("# Usage: curl -H \"Authorization: Bearer $TOKEN\" ...")

    # Test endpoints if requested
    if args.test:
        if not args.tenant_id:
            print("❌ --tenant-id is required when using --test")
            sys.exit(1)
        test_organization_endpoints(token, args.tenant_id, args.api_base, verify_tls=verify_tls)

if __name__ == "__main__":
    main()
