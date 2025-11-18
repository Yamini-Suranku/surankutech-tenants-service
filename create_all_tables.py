#!/usr/bin/env python3
"""
Create all database tables for tenants service
"""

import os
import sys
import logging
from pathlib import Path

# Add current directory to Python path
sys.path.append(str(Path(__file__).parent))

from shared.database import engine, Base, check_db_connection

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_all_tables():
    """Create all database tables for tenants service"""
    try:
        logger.info("Starting database table creation for tenants service...")

        # Check database connection
        if not check_db_connection():
            raise Exception("Cannot connect to database")

        logger.info("Database connection successful")

        # Import all models to register them with Base.metadata
        logger.info("Importing shared models...")
        from shared.models import Tenant, User, UserTenant, TenantAppAccess, AuditLog, UserStatus

        logger.info("Importing tenants service models...")
        from models import TenantSettings, SocialAccount, PasswordResetToken

        logger.info("All models imported successfully")

        # Print all registered tables
        logger.info(f"Registered tables: {list(Base.metadata.tables.keys())}")

        # Check Base metadata
        logger.info(f"Base metadata tables count: {len(Base.metadata.tables)}")

        # Create all tables
        logger.info("Creating all tables...")
        Base.metadata.create_all(bind=engine)

        logger.info("Database table creation completed successfully!")

        # List created tables
        with engine.connect() as conn:
            from sqlalchemy import text
            result = conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"))
            tables = [row[0] for row in result]
            logger.info(f"Created tables: {sorted(tables)}")

        return True

    except Exception as e:
        logger.error(f"Database table creation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = create_all_tables()
    sys.exit(0 if success else 1)