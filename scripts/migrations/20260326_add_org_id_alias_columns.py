from sqlalchemy import text

from shared.database import engine


SYNC_FUNCTION_SQL = """
CREATE OR REPLACE FUNCTION tenants_sync_org_id_columns()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.organization_id IS NULL AND NEW.org_id IS NOT NULL THEN
        NEW.organization_id := NEW.org_id;
    ELSIF NEW.org_id IS NULL AND NEW.organization_id IS NOT NULL THEN
        NEW.org_id := NEW.organization_id;
    ELSIF NEW.organization_id IS NOT NULL AND NEW.org_id IS NOT NULL
          AND NEW.organization_id::text <> NEW.org_id::text THEN
        NEW.org_id := NEW.organization_id;
    END IF;
    RETURN NEW;
END;
$$;
"""


ADD_AND_BACKFILL_SQL = """
DO $$
DECLARE
    rec RECORD;
BEGIN
    FOR rec IN
        SELECT c.table_name,
               format_type(a.atttypid, a.atttypmod) AS data_type,
               c.is_nullable
        FROM information_schema.columns c
        JOIN information_schema.tables t
          ON t.table_schema = c.table_schema
         AND t.table_name = c.table_name
        JOIN pg_class pc ON pc.relname = c.table_name
        JOIN pg_namespace pn ON pn.oid = pc.relnamespace AND pn.nspname = c.table_schema
        JOIN pg_attribute a ON a.attrelid = pc.oid AND a.attname = c.column_name
        WHERE c.table_schema = 'public'
          AND t.table_type = 'BASE TABLE'
          AND c.column_name = 'organization_id'
          AND c.table_name NOT IN (
              SELECT table_name
              FROM information_schema.columns
              WHERE table_schema = 'public' AND column_name = 'org_id'
          )
    LOOP
        EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS org_id %s', rec.table_name, rec.data_type);
        EXECUTE format('UPDATE %I SET org_id = organization_id WHERE org_id IS NULL', rec.table_name);
        IF rec.is_nullable = 'NO' THEN
            EXECUTE format('ALTER TABLE %I ALTER COLUMN org_id SET NOT NULL', rec.table_name);
        END IF;
    END LOOP;
END $$;
"""


TRIGGER_SQL = """
DO $$
DECLARE
    rec RECORD;
    trigger_name text;
BEGIN
    FOR rec IN
        SELECT table_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND column_name = 'organization_id'
          AND table_name IN (
              SELECT table_name FROM information_schema.tables
              WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
          )
        INTERSECT
        SELECT table_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND column_name = 'org_id'
          AND table_name IN (
              SELECT table_name FROM information_schema.tables
              WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
          )
    LOOP
        trigger_name := format('trg_%s_sync_org_id', rec.table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', trigger_name, rec.table_name);
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION tenants_sync_org_id_columns()',
            trigger_name,
            rec.table_name
        );
    END LOOP;
END $$;
"""


def run() -> None:
    with engine.begin() as conn:
        conn.execute(text(SYNC_FUNCTION_SQL))
        conn.execute(text(ADD_AND_BACKFILL_SQL))
        conn.execute(text(TRIGGER_SQL))
    print('Applied additive org_id compatibility migration for Tenants')


if __name__ == '__main__':
    run()
