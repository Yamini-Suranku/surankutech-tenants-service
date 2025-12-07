"""
Token Enhancement API
Provides endpoints for Keycloak to enhance JWT tokens with organization data
"""

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from typing import Dict, Any
import logging

from modules.jwt_token_enhancer import jwt_enhancer
from modules.user_attribute_sync import user_attribute_sync

logger = logging.getLogger(__name__)

# Create router for token enhancement endpoints
router = APIRouter(prefix="/api/token-enhancement", tags=["token-enhancement"])

@router.get("/user-org-memberships")
async def get_user_org_memberships(
    user_id: str = Query(..., description="Keycloak user ID (sub claim)")
) -> Dict[str, Any]:
    """
    Get user's organization memberships for JWT token enhancement
    Called by Keycloak protocol mappers to populate org_memberships claim
    """
    try:
        logger.info(f"Token enhancement request for user: {user_id}")

        org_memberships = await jwt_enhancer.get_user_org_memberships(user_id)

        response = {
            "org_memberships": org_memberships
        }

        logger.info(f"Returning {len(org_memberships)} org memberships for user {user_id}")
        return response

    except Exception as e:
        logger.error(f"Error enhancing token for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Token enhancement failed: {str(e)}")

@router.get("/user-enhanced-data")
async def get_user_enhanced_data(
    user_id: str = Query(..., description="Keycloak user ID (sub claim)")
) -> Dict[str, Any]:
    """
    Get comprehensive enhanced token data for a user
    Includes org_memberships, tenant info, and consolidated app_roles
    """
    try:
        logger.info(f"Enhanced token data request for user: {user_id}")

        enhanced_data = await jwt_enhancer.get_user_enhanced_token_data(user_id)

        logger.info(f"Returning enhanced token data for user {user_id}")
        logger.info(f"  - Org memberships: {len(enhanced_data.get('org_memberships', []))}")
        logger.info(f"  - All tenants: {enhanced_data.get('all_tenants', [])}")
        logger.info(f"  - App roles: {list(enhanced_data.get('app_roles', {}).keys())}")

        return enhanced_data

    except Exception as e:
        logger.error(f"Error getting enhanced data for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Enhanced data retrieval failed: {str(e)}")

@router.post("/sync-user-attributes")
async def sync_user_attributes(
    background_tasks: BackgroundTasks,
    user_id: str = Query(..., description="Keycloak user ID (sub claim)")
) -> Dict[str, Any]:
    """
    Synchronize user attributes in Keycloak with current organization memberships
    This updates the user's attributes so the protocol mapper can include them in JWT
    """
    try:
        logger.info(f"Sync user attributes request for user: {user_id}")

        # Sync user org memberships to Keycloak attributes
        success = await user_attribute_sync.sync_user_org_memberships(user_id)

        if success:
            return {
                "status": "success",
                "message": f"User attributes synced successfully for user {user_id}"
            }
        else:
            return {
                "status": "error",
                "message": f"Failed to sync user attributes for user {user_id}"
            }

    except Exception as e:
        logger.error(f"Error syncing user attributes for {user_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Attribute sync failed: {str(e)}")

@router.post("/sync-all-users")
async def sync_all_users(background_tasks: BackgroundTasks) -> Dict[str, Any]:
    """
    Bulk synchronization of all user attributes
    This is for initial setup or periodic maintenance
    """
    try:
        logger.info("Starting bulk user attribute sync")

        # Run the bulk sync in background
        background_tasks.add_task(user_attribute_sync.sync_all_users_org_memberships)

        return {
            "status": "initiated",
            "message": "Bulk user attribute sync initiated in background"
        }

    except Exception as e:
        logger.error(f"Error initiating bulk sync: {e}")
        raise HTTPException(status_code=500, detail=f"Bulk sync initiation failed: {str(e)}")

@router.get("/health")
async def health_check():
    """Health check endpoint for token enhancement service"""
    return {
        "status": "healthy",
        "service": "token-enhancement",
        "message": "Token enhancement service is running"
    }