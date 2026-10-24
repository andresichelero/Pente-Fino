-- ==============================================================================
-- PenteFino PostgreSQL Bootstrap Script
-- Path: docker/postgres/init.sql
-- Mounted to: /docker-entrypoint-initdb.d/init.sql
-- Enables pgcrypto extension for cryptographic digests and HMACs prior to migrations
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Verify extension registration
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto'
    ) THEN
        RAISE NOTICE 'PenteFino database bootstrap: pgcrypto extension enabled successfully.';
    ELSE
        RAISE EXCEPTION 'pgcrypto extension failed to initialize';
    END IF;
END $$;
