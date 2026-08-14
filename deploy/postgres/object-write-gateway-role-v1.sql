-- Install the dedicated object-write gateway login after the clean-slate
-- control schema has been created. Invoke with psql variables:
--   -v control_database=cats -v control_schema=cats_control
--
-- This pre-composition script grants the eleven routines present in this
-- leaf. The daemon still refuses startup because the E13-owned qualification
-- lock is absent; the final composition must add that exact twelfth grant and
-- flip the attested capability only after installing the reviewed routine.
-- Password creation/rotation belongs to the platform secret workflow.
\set ON_ERROR_STOP on

BEGIN;

DO $role$
DECLARE
    membership RECORD;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='cats_object_write_gateway') THEN
        CREATE ROLE cats_object_write_gateway
            LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS;
    ELSE
        ALTER ROLE cats_object_write_gateway
            LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS;
    END IF;

    FOR membership IN
        SELECT granted.rolname AS granted_role
          FROM pg_auth_members member
          JOIN pg_roles granted ON granted.oid=member.roleid
          JOIN pg_roles gateway ON gateway.oid=member.member
         WHERE gateway.rolname='cats_object_write_gateway'
    LOOP
        EXECUTE format(
            'REVOKE %I FROM cats_object_write_gateway',
            membership.granted_role
        );
    END LOOP;
END;
$role$;

REVOKE ALL ON DATABASE :"control_database" FROM cats_object_write_gateway;
REVOKE CREATE, TEMPORARY ON DATABASE :"control_database" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"control_database" TO cats_object_write_gateway;
REVOKE ALL ON SCHEMA :"control_schema" FROM cats_object_write_gateway;
GRANT USAGE ON SCHEMA :"control_schema" TO cats_object_write_gateway;
REVOKE ALL ON ALL TABLES IN SCHEMA :"control_schema"
    FROM cats_object_write_gateway;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA :"control_schema"
    FROM cats_object_write_gateway;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA :"control_schema"
    FROM cats_object_write_gateway;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA :"control_schema" FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
    :"control_schema".control_object_write_gateway_startup_v1()
    TO cats_object_write_gateway;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_object_write_gateway_register_v1(
        TEXT,TEXT,JSONB,JSONB)
    TO cats_object_write_gateway;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_object_write_gateway_begin_ingress_v1(JSONB,JSONB)
    TO cats_object_write_gateway;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_object_write_gateway_spool_durable_v1(TEXT,JSONB)
    TO cats_object_write_gateway;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_object_write_gateway_accept_v1(TEXT)
    TO cats_object_write_gateway;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_object_write_gateway_provider_issued_v1(TEXT)
    TO cats_object_write_gateway;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_object_write_gateway_terminal_v1(TEXT,BYTEA)
    TO cats_object_write_gateway;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_object_write_gateway_spool_removed_v1(TEXT,TEXT)
    TO cats_object_write_gateway;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_object_write_gateway_recover_ingress_v1(TEXT)
    TO cats_object_write_gateway;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_object_write_gateway_recover_accepted_v1(TEXT)
    TO cats_object_write_gateway;
GRANT EXECUTE ON FUNCTION
    :"control_schema".control_object_write_gateway_qualification_response_lost_v1(BYTEA,BYTEA)
    TO cats_object_write_gateway;

ALTER ROLE cats_object_write_gateway SET search_path TO :"control_schema";

COMMIT;
