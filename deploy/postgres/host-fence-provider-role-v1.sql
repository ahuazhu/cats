-- Install the dedicated Host-fence provider login after the clean-slate
-- control schema has been created. Invoke with psql variables:
--   -v control_database=cats -v control_schema=cats_control
-- Password creation/rotation belongs to the platform secret workflow and is
-- deliberately not accepted by this checked-in script.
\set ON_ERROR_STOP on

BEGIN;

DO $role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='cats_host_fence_provider') THEN
        CREATE ROLE cats_host_fence_provider
            LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS;
    ELSE
        ALTER ROLE cats_host_fence_provider
            LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS;
    END IF;
END;
$role$;

GRANT CONNECT ON DATABASE :"control_database" TO cats_host_fence_provider;
REVOKE CREATE ON SCHEMA :"control_schema" FROM cats_host_fence_provider;
GRANT USAGE ON SCHEMA :"control_schema" TO cats_host_fence_provider;
REVOKE ALL ON ALL TABLES IN SCHEMA :"control_schema"
    FROM cats_host_fence_provider;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA :"control_schema"
    FROM cats_host_fence_provider;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA :"control_schema"
    FROM cats_host_fence_provider;

GRANT EXECUTE ON FUNCTION
    :"control_schema".control_host_fence_provider_startup_v1()
    TO cats_host_fence_provider;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_host_fence_provider_claim_v1(
        TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,BIGINT)
    TO cats_host_fence_provider;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_host_fence_provider_renew_v1(
        TEXT,TEXT,TEXT,BIGINT)
    TO cats_host_fence_provider;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_host_fence_provider_object_cutoff_v1(TEXT,TEXT)
    TO cats_host_fence_provider;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_host_fence_provider_complete_v1(
        TEXT,TEXT,BYTEA,TEXT)
    TO cats_host_fence_provider;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_host_fence_provider_read_v1(TEXT,TEXT)
    TO cats_host_fence_provider;

ALTER ROLE cats_host_fence_provider SET search_path TO :"control_schema";

COMMIT;
