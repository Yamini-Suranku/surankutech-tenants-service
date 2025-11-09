#!/usr/bin/env python3
"""
Database initialization script for Suranku Platform
Creates all necessary tables for the tenants service
"""

import os
import sys
import logging
from pathlib import Path

# Add services to Python path
sys.path.append(str(Path(__file__).parent.parent))

from shared.database import engine, create_tables, check_db_connection
from shared.models import Base, Tenant, User, UserTenant, TenantAppAccess, FeatureFlag, AuditLog
from tenants.models import Invitation, TenantSettings, SocialAccount, TenantApiKey, TenantDomain

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def initialize_database():
    """Initialize database with all required tables"""
    try:
        logger.info("Starting database initialization...")

        # Check database connection
        if not check_db_connection():
            raise Exception("Cannot connect to database")

        logger.info("Database connection successful")

        # Create all tables from both shared and tenant models
        logger.info("Creating database tables...")

        # Import all models to register them with Base.metadata
        from shared.models import Tenant, User, UserTenant, TenantAppAccess, FeatureFlag, AuditLog
        from tenants.models import Invitation, TenantSettings, SocialAccount, TenantApiKey, TenantDomain

        logger.info("Imported models successfully")

        # Create all tables
        Base.metadata.create_all(bind=engine)

        logger.info("Database initialization completed successfully!")

        # List created tables by connecting to the database
        with engine.connect() as conn:
            from sqlalchemy import text
            result = conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"))
            tables = [row[0] for row in result]
            logger.info(f"Created tables: {sorted(tables)}")

        return True

    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

if __name__ == "__main__":
    success = initialize_database()
    sys.exit(0 if success else 1)