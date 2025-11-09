from sqlalchemy import create_engine, MetaData, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import os
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:password@localhost:5432/suranku_platform"
)

# Create engine with connection pooling
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    echo=os.getenv("SQL_DEBUG", "false").lower() == "true"
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Metadata for migrations
metadata = MetaData()

def get_db():
    """Database dependency for FastAPI"""
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        logger.error(f"Database error: {e}")
        db.rollback()
        raise
    finally:
        db.close()

@contextmanager
def get_db_session():
    """Context manager for database sessions"""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        logger.error(f"Database transaction error: {e}")
        db.rollback()
        raise
    finally:
        db.close()

def create_tables():
    """Create all tables in database"""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise

def check_db_connection():
    """Health check for database connection"""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False

class TenantMixin:
    """Mixin for tenant isolation in models"""
    def filter_by_tenant(self, query, tenant_id: str):
        """Filter query by tenant_id"""
        return query.filter(self.tenant_id == tenant_id)

    @classmethod
    def get_by_tenant(cls, db, tenant_id: str):
        """Get all records for a specific tenant"""
        return db.query(cls).filter(cls.tenant_id == tenant_id).all()

    @classmethod
    def get_by_id_and_tenant(cls, db, record_id: str, tenant_id: str):
        """Get specific record by ID and tenant"""
        return db.query(cls).filter(
            cls.id == record_id,
            cls.tenant_id == tenant_id
        ).first()

def ensure_tenant_isolation(func):
    """Decorator to ensure tenant isolation in database operations"""
    def wrapper(*args, **kwargs):
        # Add tenant_id validation logic here
        return func(*args, **kwargs)
    return wrapper