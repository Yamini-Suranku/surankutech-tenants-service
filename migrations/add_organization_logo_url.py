from sqlalchemy import text

from shared.database import engine


DDL = """
ALTER TABLE organizations
ADD COLUMN IF NOT EXISTS logo_url VARCHAR(500) NULL;
"""


def migrate() -> None:
    with engine.begin() as connection:
        for statement in [part.strip() for part in DDL.split(";") if part.strip()]:
            connection.execute(text(statement))


if __name__ == "__main__":
    migrate()
    print("organization.logo_url migration applied")
