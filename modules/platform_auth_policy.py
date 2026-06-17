"""Platform-wide authentication policy helpers."""

from datetime import datetime
from typing import Iterable, List

from sqlalchemy.orm import Session

from models import PlatformAuthSettings

ALLOWED_SOCIAL_PROVIDERS = {"google", "github", "microsoft"}
DEFAULT_SOCIAL_PROVIDERS = ["google", "github", "microsoft"]


def get_platform_auth_settings(db: Session) -> PlatformAuthSettings:
    settings = db.query(PlatformAuthSettings).filter(PlatformAuthSettings.id == "default").first()
    if settings:
        return settings

    settings = PlatformAuthSettings(
        id="default",
        social_login_enabled=True,
        tenant_approval_required=False,
        enabled_social_providers=list(DEFAULT_SOCIAL_PROVIDERS),
    )
    db.add(settings)
    db.commit()
    db.refresh(settings)
    return settings


def normalize_social_providers(providers: Iterable[str] | None) -> List[str]:
    if providers is None:
        return list(DEFAULT_SOCIAL_PROVIDERS)

    normalized = []
    for provider in providers:
        value = str(provider or "").strip().lower()
        if value in ALLOWED_SOCIAL_PROVIDERS and value not in normalized:
            normalized.append(value)
    return normalized or list(DEFAULT_SOCIAL_PROVIDERS)


def update_platform_auth_settings(
    db: Session,
    *,
    social_login_enabled: bool | None = None,
    tenant_approval_required: bool | None = None,
    enabled_social_providers: Iterable[str] | None = None,
    updated_by: str | None = None,
) -> PlatformAuthSettings:
    settings = get_platform_auth_settings(db)

    if social_login_enabled is not None:
        settings.social_login_enabled = bool(social_login_enabled)
    if tenant_approval_required is not None:
        settings.tenant_approval_required = bool(tenant_approval_required)
    if enabled_social_providers is not None:
        settings.enabled_social_providers = normalize_social_providers(enabled_social_providers)
    if updated_by:
        settings.updated_by = updated_by

    settings.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(settings)
    return settings


def serialize_platform_auth_settings(settings: PlatformAuthSettings) -> dict:
    signup_approval_required = bool(settings.tenant_approval_required)
    return {
        "social_login_enabled": bool(settings.social_login_enabled),
        # Keep the legacy field until the DB column can be renamed safely.
        "tenant_approval_required": signup_approval_required,
        "platform_signup_approval_required": signup_approval_required,
        "enabled_social_providers": normalize_social_providers(settings.enabled_social_providers),
        "updated_by": settings.updated_by,
        "updated_at": settings.updated_at.isoformat() if settings.updated_at else None,
    }
