-- Exact least-privilege PostgreSQL surface for cats-object-write-gatewayd.
-- The release installer substitutes the two schema placeholders. This
-- pre-composition leaf installs startup, nine semantic routines, and the
-- V3 response-loss routine. The E13 qualification-lock routine is deliberately
-- absent, so startup reports that the required twelve-routine production
-- surface is unavailable. The framing helper is private to the owner.

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(value BYTEA)
RETURNS BYTEA
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT pg_catalog.int8send(pg_catalog.octet_length(value)::BIGINT) || value
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(BYTEA) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_startup_v1()
RETURNS TABLE(
    protocol_version BIGINT,
    schema_version BIGINT,
    schema_name TEXT,
    expected_role TEXT,
    routine_count BIGINT,
    contract_sha256 TEXT,
    catalog_sha256 TEXT,
    qualification_lock_available BOOLEAN
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    catalog_input TEXT;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway' THEN
        RAISE EXCEPTION 'object-write gateway PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    SELECT pg_catalog.string_agg(
               function.proname || pg_catalog.chr(1) ||
               pg_catalog.pg_get_function_identity_arguments(function.oid) ||
               pg_catalog.chr(1) ||
               pg_catalog.pg_get_function_result(function.oid) ||
               pg_catalog.chr(1) || function.prosecdef::TEXT ||
               pg_catalog.chr(1) || function.proisstrict::TEXT ||
               pg_catalog.chr(1) || function.provolatile::TEXT ||
               pg_catalog.chr(1) || language.lanname ||
               pg_catalog.chr(1) || COALESCE(
                   pg_catalog.array_to_string(function.proconfig, ','), '') ||
               pg_catalog.chr(1) ||
                   (function.proowner=namespace.nspowner)::TEXT ||
               pg_catalog.chr(1) || (NOT EXISTS (
                   SELECT 1
                     FROM pg_catalog.aclexplode(COALESCE(
                          function.proacl,
                          pg_catalog.acldefault('f', function.proowner)
                     )) privilege
                    WHERE privilege.grantee=0
                      AND privilege.privilege_type='EXECUTE'
               ))::TEXT ||
               pg_catalog.chr(1) || pg_catalog.has_function_privilege(
                   session_user, function.oid, 'EXECUTE')::TEXT ||
               pg_catalog.chr(1) || pg_catalog.encode(pg_catalog.sha256(
                   pg_catalog.convert_to(
                       pg_catalog.replace(pg_catalog.replace(pg_catalog.replace(
                               function.prosrc,
                               pg_catalog.chr(34) || __CATS_SCHEMA_LITERAL__ || pg_catalog.chr(34),
                               '__CATS_SCHEMA_' || 'IDENT__'
                           ), pg_catalog.quote_literal(__CATS_SCHEMA_LITERAL__),
                              '__CATS_SCHEMA_' || 'LITERAL__'),
                           '__CATS_OBJECT_WRITE_GATEWAY_CONTRACT_SHA256_VALUE__',
                           '__CATS_OBJECT_WRITE_GATEWAY_' ||
                               'CONTRACT_SHA256_VALUE__'),
                       'UTF8'
                   )), 'hex'),
               pg_catalog.chr(10)
               ORDER BY function.proname
           )
      INTO catalog_input
      FROM pg_catalog.pg_proc function
      JOIN pg_catalog.pg_namespace namespace
        ON namespace.oid=function.pronamespace
      JOIN pg_catalog.pg_language language ON language.oid=function.prolang
     WHERE namespace.nspname=__CATS_SCHEMA_LITERAL__
       AND function.proname = ANY(ARRAY[
           'control_object_write_gateway_frame_v1',
           'control_object_write_gateway_startup_v1',
           'control_object_write_gateway_register_v1',
           'control_object_write_gateway_begin_ingress_v1',
           'control_object_write_gateway_spool_durable_v1',
           'control_object_write_gateway_accept_v1',
           'control_object_write_gateway_provider_issued_v1',
           'control_object_write_gateway_qualification_head_canonical_v1',
           'control_object_write_gateway_qualification_response_lost_v1',
           'control_object_write_gateway_terminal_v1',
           'control_object_write_gateway_spool_removed_v1',
           'control_object_write_gateway_recover_ingress_v1',
           'control_object_write_gateway_recover_accepted_v1',
           'control_object_write_gateway_qualification_lock_v1'
       ]::TEXT[]);
    RETURN QUERY SELECT
        1::BIGINT,
        (
            SELECT stamp.version
              FROM __CATS_SCHEMA_IDENT__.control_schema_version stamp
             WHERE stamp.singleton
        )::BIGINT,
        __CATS_SCHEMA_LITERAL__::TEXT,
        'cats_object_write_gateway'::TEXT,
        12::BIGINT,
        'sha256:__CATS_OBJECT_WRITE_GATEWAY_CONTRACT_SHA256_VALUE__'::TEXT,
        'sha256:' || pg_catalog.encode(
            pg_catalog.sha256(pg_catalog.convert_to(catalog_input, 'UTF8')), 'hex'),
        -- Attested, never asserted: the capability is true only when the E13
        -- routine is installed in this schema and this exact login may execute
        -- it. A missing grant reports false and the daemon refuses to start.
        (
            SELECT COALESCE(pg_catalog.bool_or(
                pg_catalog.has_function_privilege(
                    session_user, function.oid, 'EXECUTE')), FALSE)
              FROM pg_catalog.pg_proc function
              JOIN pg_catalog.pg_namespace namespace
                ON namespace.oid=function.pronamespace
             WHERE namespace.nspname=__CATS_SCHEMA_LITERAL__
               AND function.proname='control_object_write_gateway_qualification_lock_v1'
        );
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_startup_v1() FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_register_v1(
    requested_node_credential_id TEXT,
    requested_node_public_key_sha256 TEXT,
    requested_attachment JSONB,
    requested_registration JSONB
)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    now_ms BIGINT;
    identity_row RECORD;
    session_row RECORD;
    volume_row RECORD;
    authority_row RECORD;
    existing_row RECORD;
    binding JSONB;
    receipt JSONB;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway' THEN
        RAISE EXCEPTION 'object-write gateway PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF pg_catalog.pg_column_size(requested_registration) > 32768
       OR pg_catalog.pg_column_size(requested_attachment) > 4096
       OR pg_catalog.jsonb_typeof(requested_registration) IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*)
             FROM pg_catalog.jsonb_object_keys(requested_registration)) <> 11
       OR pg_catalog.jsonb_typeof(requested_registration -> 'session')
            IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(
            requested_registration -> 'session')) <> 4
       OR pg_catalog.jsonb_typeof(requested_registration -> 'credential')
            IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(
            requested_registration -> 'credential')) <> 2
       OR pg_catalog.jsonb_typeof(requested_attachment) IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*)
             FROM pg_catalog.jsonb_object_keys(requested_attachment)) <> 2
       OR requested_registration #>> '{version}' IS DISTINCT FROM '1'
       OR requested_registration #>> '{session,node_id}' IS NULL
       OR requested_registration #>> '{writer_authority_id}' IS NULL
       OR requested_registration #>> '{volume_id}' IS NULL
       OR requested_registration #>> '{attachment_id}' IS NULL
       OR COALESCE((requested_registration #>> '{attachment_epoch}')::BIGINT, 0) <= 0
       OR requested_attachment IS DISTINCT FROM requested_registration -> 'credential'
       OR requested_node_public_key_sha256 !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'object-write registration is invalid'
            USING ERRCODE = '22023';
    END IF;

    SELECT identity.* INTO identity_row
      FROM __CATS_SCHEMA_IDENT__.node_identities identity
     WHERE identity.credential_id=requested_node_credential_id
     FOR UPDATE;
    IF NOT FOUND
       OR identity_row.state <> 'provisioned'
       OR identity_row.credential_kind <> 'public_key'
       OR identity_row.credential_public_key_spki_sha256
            IS DISTINCT FROM requested_node_public_key_sha256
       OR identity_row.credential_lineage_state <> 'active'
       OR identity_row.node_id
            IS DISTINCT FROM requested_registration #>> '{session,node_id}' THEN
        RAISE EXCEPTION 'object-write Node credential is not current'
            USING ERRCODE = '42501';
    END IF;
    PERFORM 1
      FROM __CATS_SCHEMA_IDENT__.runtime_node_credential_lineage lineage
     WHERE lineage.credential_id=requested_node_credential_id
       AND lineage.node_id=identity_row.node_id
       AND lineage.public_key_spki_sha256=requested_node_public_key_sha256
       AND lineage.state='active'
     FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write Node credential lineage is not active'
            USING ERRCODE = '42501';
    END IF;

    SELECT session.* INTO session_row
      FROM __CATS_SCHEMA_IDENT__.current_agent_sessions session
     WHERE session.node_id=identity_row.node_id
     FOR UPDATE;
    now_ms := pg_catalog.floor(
        pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    IF NOT FOUND
       OR session_row.immutable_host_id IS DISTINCT FROM identity_row.immutable_host_id
       OR session_row.node_boot_id
            IS DISTINCT FROM requested_registration #>> '{session,node_boot_id}'
       OR session_row.agent_instance_id
            IS DISTINCT FROM requested_registration #>> '{session,agent_instance_id}'
       OR session_row.agent_session_epoch
            IS DISTINCT FROM (requested_registration #>> '{session,agent_session_epoch}')::BIGINT
       OR session_row.lease_deadline_unix_ms < now_ms THEN
        RAISE EXCEPTION 'object-write registration has no exact current AgentSession'
            USING ERRCODE = '55000';
    END IF;

    SELECT volume.* INTO volume_row
      FROM __CATS_SCHEMA_IDENT__.volume_records volume
     WHERE volume.volume_id=requested_registration #>> '{volume_id}'
     FOR SHARE;
    IF NOT FOUND
       OR volume_row.admin_state <> 'active'
       OR volume_row.owner_node_id IS DISTINCT FROM identity_row.node_id
       OR volume_row.lease_owner
            IS DISTINCT FROM requested_registration #>> '{attachment_id}'
       OR volume_row.lease_epoch
            IS DISTINCT FROM (requested_registration #>> '{attachment_epoch}')::BIGINT
       OR volume_row.lease_expires_at IS NULL
       OR volume_row.lease_expires_at < now_ms THEN
        RAISE EXCEPTION 'object-write registration does not bind current Volume owner'
            USING ERRCODE = '55000';
    END IF;

    SELECT authority.* INTO authority_row
      FROM __CATS_SCHEMA_IDENT__.object_write_authorities authority
     WHERE authority.writer_authority_id=
        requested_registration #>> '{writer_authority_id}'
     FOR UPDATE;
    IF NOT FOUND
       OR authority_row.state <> 'open'
       OR authority_row.node_id IS DISTINCT FROM identity_row.node_id
       OR authority_row.host_provider IS DISTINCT FROM identity_row.host_provider
       OR authority_row.host_partition IS DISTINCT FROM identity_row.host_partition
       OR authority_row.host_account_id IS DISTINCT FROM identity_row.host_account_id
       OR authority_row.host_region IS DISTINCT FROM identity_row.host_region
       OR authority_row.immutable_host_id IS DISTINCT FROM identity_row.immutable_host_id THEN
        RAISE EXCEPTION 'object-write authority is missing, closed, or changed'
            USING ERRCODE = '55000';
    END IF;

    SELECT credential.* INTO existing_row
      FROM __CATS_SCHEMA_IDENT__.object_write_credentials credential
     WHERE credential.credential_id=
        requested_registration #>> '{credential,credential_id}'
     FOR UPDATE;
    IF FOUND THEN
        binding := pg_catalog.jsonb_build_object(
            'credential', requested_registration -> 'credential',
            'public_key_spki', requested_registration -> 'public_key_spki',
            'writer_authority_id', requested_registration -> 'writer_authority_id',
            'host_provider_scope', authority_row.record #> '{writer,host_provider_scope}',
            'immutable_host_id', authority_row.record #> '{writer,immutable_host_id}',
            'node_id', requested_registration #> '{session,node_id}',
            'node_boot_id', requested_registration #> '{session,node_boot_id}',
            'agent_instance_id', requested_registration #> '{session,agent_instance_id}',
            'agent_session_epoch', requested_registration #> '{session,agent_session_epoch}',
            'volume_id', requested_registration -> 'volume_id',
            'attachment_id', requested_registration -> 'attachment_id',
            'attachment_epoch', requested_registration -> 'attachment_epoch',
            'private_artifact_id', requested_registration -> 'private_artifact_id',
            'private_file_fsync_receipt_id',
                requested_registration -> 'private_file_fsync_receipt_id',
            'private_directory_fsync_receipt_id',
                requested_registration -> 'private_directory_fsync_receipt_id',
            'registered_at_unix_ms', pg_catalog.to_jsonb(existing_row.registered_at_unix_ms),
            'state', pg_catalog.jsonb_build_object('kind', 'active')
        );
        IF existing_row.state <> 'active' OR existing_row.record IS DISTINCT FROM binding THEN
            RAISE EXCEPTION 'object-write credential replay changed immutable binding'
                USING ERRCODE = '55000';
        END IF;
    ELSE
        binding := pg_catalog.jsonb_build_object(
            'credential', requested_registration -> 'credential',
            'public_key_spki', requested_registration -> 'public_key_spki',
            'writer_authority_id', requested_registration -> 'writer_authority_id',
            'host_provider_scope', authority_row.record #> '{writer,host_provider_scope}',
            'immutable_host_id', authority_row.record #> '{writer,immutable_host_id}',
            'node_id', requested_registration #> '{session,node_id}',
            'node_boot_id', requested_registration #> '{session,node_boot_id}',
            'agent_instance_id', requested_registration #> '{session,agent_instance_id}',
            'agent_session_epoch', requested_registration #> '{session,agent_session_epoch}',
            'volume_id', requested_registration -> 'volume_id',
            'attachment_id', requested_registration -> 'attachment_id',
            'attachment_epoch', requested_registration -> 'attachment_epoch',
            'private_artifact_id', requested_registration -> 'private_artifact_id',
            'private_file_fsync_receipt_id',
                requested_registration -> 'private_file_fsync_receipt_id',
            'private_directory_fsync_receipt_id',
                requested_registration -> 'private_directory_fsync_receipt_id',
            'registered_at_unix_ms', pg_catalog.to_jsonb(now_ms),
            'state', pg_catalog.jsonb_build_object('kind', 'active')
        );
        INSERT INTO __CATS_SCHEMA_IDENT__.object_write_credentials (
            credential_id, record, public_key_spki, public_key_spki_sha256,
            writer_authority_id, host_provider, host_partition,
            host_account_id, host_region, immutable_host_id, node_id,
            node_boot_id, agent_instance_id, agent_session_epoch, volume_id,
            attachment_id, attachment_epoch, private_artifact_id,
            private_file_fsync_receipt_id,
            private_directory_fsync_receipt_id, registered_at_unix_ms, state
        ) VALUES (
            requested_registration #>> '{credential,credential_id}', binding,
            requested_registration #>> '{public_key_spki}',
            requested_registration #>> '{credential,public_key_spki_sha256}',
            authority_row.writer_authority_id,
            authority_row.host_provider, authority_row.host_partition,
            authority_row.host_account_id, authority_row.host_region,
            authority_row.immutable_host_id, identity_row.node_id,
            requested_registration #>> '{session,node_boot_id}',
            requested_registration #>> '{session,agent_instance_id}',
            (requested_registration #>> '{session,agent_session_epoch}')::BIGINT,
            requested_registration #>> '{volume_id}',
            requested_registration #>> '{attachment_id}',
            (requested_registration #>> '{attachment_epoch}')::BIGINT,
            requested_registration #>> '{private_artifact_id}',
            requested_registration #>> '{private_file_fsync_receipt_id}',
            requested_registration #>> '{private_directory_fsync_receipt_id}',
            now_ms, 'active'
        );
    END IF;

    receipt := pg_catalog.jsonb_build_object(
        'version', 1,
        'writer_authority_id', requested_registration -> 'writer_authority_id',
        'volume_id', requested_registration -> 'volume_id',
        'attachment_id', requested_registration -> 'attachment_id',
        'attachment_epoch', requested_registration -> 'attachment_epoch',
        'credential', requested_registration -> 'credential',
        'registered_at_unix_ms', binding -> 'registered_at_unix_ms'
    );
    RETURN receipt;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_register_v1(
        TEXT,TEXT,JSONB,JSONB) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_begin_ingress_v1(
    requested_attachment JSONB,
    requested_descriptor JSONB
)
RETURNS TABLE(record_json TEXT, authority_json TEXT, accepted BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    credential_row RECORD;
    authority_row RECORD;
    existing_row RECORD;
    key_kind TEXT;
    object_key TEXT;
    content_sha256 TEXT;
    content_length BIGINT;
    computed_request_id TEXT;
    hash_input BYTEA;
    target JSONB;
    ingress_record JSONB;
    now_ms BIGINT;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway' THEN
        RAISE EXCEPTION 'object-write gateway PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF pg_catalog.pg_column_size(requested_descriptor) > 16384
       OR pg_catalog.pg_column_size(requested_attachment) > 4096
       OR pg_catalog.jsonb_typeof(requested_descriptor) IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*)
             FROM pg_catalog.jsonb_object_keys(requested_descriptor)) <> 6
       OR pg_catalog.jsonb_typeof(requested_attachment) IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*)
             FROM pg_catalog.jsonb_object_keys(requested_attachment)) <> 2 THEN
        RAISE EXCEPTION 'object-write ingress descriptor frame is invalid'
            USING ERRCODE = '22023';
    END IF;
    content_sha256 := requested_descriptor #>> '{content_sha256}';
    content_length := (requested_descriptor #>> '{content_length}')::BIGINT;
    key_kind := requested_descriptor #>> '{key,kind}';
    IF requested_descriptor #>> '{version}' IS DISTINCT FROM '1'
       OR requested_attachment #>> '{credential_id}' IS NULL
       OR requested_attachment #>> '{public_key_spki_sha256}'
            !~ '^sha256:[0-9a-f]{64}$'
       OR requested_descriptor #>> '{volume_id}' IS NULL
       OR NOT (requested_descriptor ? 'qualification_fault')
       OR content_sha256 !~ '^sha256:[0-9a-f]{64}$'
       OR content_length NOT BETWEEN 0 AND 33554432 THEN
        RAISE EXCEPTION 'object-write ingress descriptor is invalid'
            USING ERRCODE = '22023';
    END IF;

    SELECT credential.writer_authority_id INTO credential_row
      FROM __CATS_SCHEMA_IDENT__.object_write_credentials credential
     WHERE credential.credential_id=requested_attachment #>> '{credential_id}';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown object-write attachment credential'
            USING ERRCODE = '42501';
    END IF;
    SELECT authority.* INTO authority_row
      FROM __CATS_SCHEMA_IDENT__.object_write_authorities authority
     WHERE authority.writer_authority_id=credential_row.writer_authority_id
     FOR UPDATE;
    SELECT credential.* INTO credential_row
      FROM __CATS_SCHEMA_IDENT__.object_write_credentials credential
     WHERE credential.credential_id=requested_attachment #>> '{credential_id}'
     FOR UPDATE;
    IF authority_row.writer_authority_id IS NULL
       OR authority_row.state <> 'open'
       OR credential_row.state <> 'active'
       OR credential_row.writer_authority_id <> authority_row.writer_authority_id
       OR credential_row.volume_id
            IS DISTINCT FROM requested_descriptor #>> '{volume_id}'
       OR credential_row.public_key_spki_sha256
            IS DISTINCT FROM requested_attachment #>> '{public_key_spki_sha256}' THEN
        RAISE EXCEPTION 'object-write attachment authority is closed or changed'
            USING ERRCODE = '55000';
    END IF;

    IF key_kind = 'volume_data' THEN
        IF pg_catalog.jsonb_typeof(requested_descriptor -> 'key')
                IS DISTINCT FROM 'object'
           OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(
                requested_descriptor -> 'key')) <> 4
           OR requested_descriptor #>> '{key,transaction_id}' !~ '^[0-9a-f]{32}$'
           OR COALESCE((requested_descriptor #>> '{key,chunk_index}')::BIGINT, -1) < 0
           OR requested_descriptor #>> '{key,object_kind}' NOT IN ('base','delta') THEN
            RAISE EXCEPTION 'object-write volume data key is invalid'
                USING ERRCODE = '22023';
        END IF;
        object_key := 'volumes/' || (requested_descriptor #>> '{volume_id}') ||
            '/data/' || (requested_descriptor #>> '{key,transaction_id}') || '-c' ||
            (requested_descriptor #>> '{key,chunk_index}') ||
            CASE requested_descriptor #>> '{key,object_kind}'
                WHEN 'delta' THEN '-d' ELSE '' END;
    ELSIF key_kind = 'volume_map' THEN
        IF pg_catalog.jsonb_typeof(requested_descriptor -> 'key')
                IS DISTINCT FROM 'object'
           OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(
                requested_descriptor -> 'key')) <> 1 THEN
            RAISE EXCEPTION 'object-write volume map key is invalid'
                USING ERRCODE = '22023';
        END IF;
        object_key := 'volumes/' || (requested_descriptor #>> '{volume_id}') ||
            '/maps/' || pg_catalog.substr(content_sha256, 8) || '.node';
    ELSIF key_kind = 'volume_commit' THEN
        IF pg_catalog.jsonb_typeof(requested_descriptor -> 'key')
                IS DISTINCT FROM 'object'
           OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(
                requested_descriptor -> 'key')) <> 3
           OR COALESCE((requested_descriptor #>> '{key,generation}')::BIGINT, 0) <= 0
           OR requested_descriptor #>> '{key,transaction_id}' !~ '^[0-9a-f]{32}$' THEN
            RAISE EXCEPTION 'object-write volume commit key is invalid'
                USING ERRCODE = '22023';
        END IF;
        object_key := 'volumes/' || (requested_descriptor #>> '{volume_id}') ||
            '/commits/' || (requested_descriptor #>> '{key,generation}') || '-' ||
            (requested_descriptor #>> '{key,transaction_id}') || '.json';
    ELSE
        RAISE EXCEPTION 'object-write key class is invalid'
            USING ERRCODE = '22023';
    END IF;

    target := pg_catalog.jsonb_build_object(
        'object_provider_scope', authority_row.record #> '{writer,object_provider_scope}',
        'object_store_scope_id', authority_row.record #> '{writer,object_store_scope_id}',
        'canonical_logical_key', object_key
    );
    hash_input :=
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to('cats.object-write-request.v1', 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to(authority_row.writer_authority_id, 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to(authority_row.object_provider, 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to(authority_row.object_partition, 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to(authority_row.object_account_id, 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to(authority_row.object_region, 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to(authority_row.object_store_scope_id, 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to(requested_descriptor #>> '{volume_id}', 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to(object_key, 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to(content_sha256, 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.int8send(content_length));
    IF requested_descriptor -> 'qualification_fault' <> 'null'::JSONB THEN
        IF pg_catalog.jsonb_typeof(requested_descriptor -> 'qualification_fault')
                IS DISTINCT FROM 'object'
           OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(
                requested_descriptor -> 'qualification_fault')) <> 4
           OR requested_descriptor #>> '{qualification_fault,kind}'
                IS DISTINCT FROM 'successful_put_response_loss'
           OR requested_descriptor #>> '{qualification_fault,qualification_id}' IS NULL
           OR requested_descriptor #>> '{qualification_fault,fault_id}'
                !~ '^[0-9a-f]{32}$'
           OR requested_descriptor #>>
                '{qualification_fault,qualification_catalog_sha256}'
                !~ '^sha256:[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'object-write qualification fault is invalid'
                USING ERRCODE = '22023';
        END IF;
        hash_input := hash_input ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.convert_to('qualification-credential', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.convert_to(
                    requested_attachment #>> '{credential_id}', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.convert_to(
                    requested_attachment #>> '{public_key_spki_sha256}', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.convert_to(
                    'qualification-fault:successful-put-response-loss', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.convert_to(
                    requested_descriptor #>>
                        '{qualification_fault,qualification_id}', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.convert_to(
                    requested_descriptor #>> '{qualification_fault,fault_id}', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.convert_to(
                    requested_descriptor #>>
                        '{qualification_fault,qualification_catalog_sha256}', 'UTF8'));
    END IF;
    computed_request_id :=
        'sha256:' || pg_catalog.encode(pg_catalog.sha256(hash_input), 'hex');
    now_ms := pg_catalog.floor(
        pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    ingress_record := pg_catalog.jsonb_build_object(
        'ingress', pg_catalog.jsonb_build_object(
            'writer_authority_id', authority_row.writer_authority_id,
            'request_id', computed_request_id,
            'credential', requested_attachment,
            'volume_id', requested_descriptor -> 'volume_id',
            'key', requested_descriptor -> 'key',
            'target', target,
            'content_sha256', requested_descriptor -> 'content_sha256',
            'content_length', requested_descriptor -> 'content_length',
            'qualification_fault', requested_descriptor -> 'qualification_fault',
            'receiving_started_at_unix_ms', now_ms
        ),
        'state', pg_catalog.jsonb_build_object('kind', 'receiving')
    );

    SELECT attempt.* INTO existing_row
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.request_id=computed_request_id
     FOR UPDATE;
    IF FOUND THEN
        IF existing_row.writer_authority_id <> authority_row.writer_authority_id
           OR existing_row.volume_id <> requested_descriptor #>> '{volume_id}'
           OR existing_row.object_key <> object_key
           OR existing_row.content_sha256 <> content_sha256
           OR existing_row.content_length <> content_length
           OR COALESCE(existing_row.record #> '{ingress,credential}',
                       existing_row.record #> '{descriptor,credential}')
                IS DISTINCT FROM requested_attachment
           OR COALESCE(existing_row.record #> '{ingress,qualification_fault}',
                       existing_row.record #> '{descriptor,qualification_fault}')
                IS DISTINCT FROM requested_descriptor -> 'qualification_fault'
           OR COALESCE(existing_row.record #> '{ingress,key}',
                       existing_row.record #> '{descriptor,key}')
                IS DISTINCT FROM requested_descriptor -> 'key' THEN
            RAISE EXCEPTION 'object-write request replay changed immutable fields'
                USING ERRCODE = '55000';
        END IF;
        RETURN QUERY SELECT existing_row.record::TEXT,
            CASE WHEN existing_row.accepted_sequence IS NULL
                 THEN NULL ELSE authority_row.record::TEXT END,
            existing_row.accepted_sequence IS NOT NULL;
        RETURN;
    END IF;

    INSERT INTO __CATS_SCHEMA_IDENT__.object_write_attempts (
        request_id, record, writer_authority_id, credential_id, volume_id,
        key_kind, object_provider, object_partition, object_account_id,
        object_region, object_store_scope_id, object_key, content_sha256,
        content_length, receiving_started_at_unix_ms, state
    ) VALUES (
        computed_request_id, ingress_record, authority_row.writer_authority_id,
        credential_row.credential_id, requested_descriptor #>> '{volume_id}',
        key_kind, authority_row.object_provider, authority_row.object_partition,
        authority_row.object_account_id, authority_row.object_region,
        authority_row.object_store_scope_id, object_key, content_sha256,
        content_length, now_ms, 'receiving'
    );
    RETURN QUERY SELECT ingress_record::TEXT, NULL::TEXT, FALSE;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_begin_ingress_v1(
        JSONB,JSONB) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_spool_durable_v1(
    requested_request_id TEXT,
    requested_spool JSONB
)
RETURNS TABLE(record_json TEXT, authority_json TEXT, accepted BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    attempt_row RECORD;
    embedded_spool JSONB;
    durable_spool JSONB;
    now_ms BIGINT;
    updated_record JSONB;
    authority_text TEXT;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway' THEN
        RAISE EXCEPTION 'object-write gateway PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF pg_catalog.pg_column_size(requested_spool) > 8192
       OR pg_catalog.jsonb_typeof(requested_spool) IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*)
             FROM pg_catalog.jsonb_object_keys(requested_spool)) <> 7 THEN
        RAISE EXCEPTION 'object-write durable spool receipt frame is invalid'
            USING ERRCODE = '22023';
    END IF;
    SELECT attempt.* INTO attempt_row
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.request_id=requested_request_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write attempt does not exist'
            USING ERRCODE = 'P0002';
    END IF;
    IF requested_spool #>> '{spool_id}'
            IS DISTINCT FROM 'owsp1_' || pg_catalog.substr(requested_request_id, 8)
       OR requested_spool #>> '{request_id}' IS DISTINCT FROM requested_request_id
       OR requested_spool #>> '{content_sha256}'
            IS DISTINCT FROM attempt_row.content_sha256
       OR (requested_spool #>> '{content_length}')::BIGINT
            IS DISTINCT FROM attempt_row.content_length
       OR requested_spool #>> '{file_fsync_receipt_id}' IS NULL
       OR requested_spool #>> '{directory_fsync_receipt_id}' IS NULL THEN
        RAISE EXCEPTION 'object-write durable spool receipt changed immutable material'
            USING ERRCODE = '22023';
    END IF;
    embedded_spool := COALESCE(
        attempt_row.record #> '{state,spool,spool}',
        attempt_row.record #> '{state,spool}'
    );
    IF attempt_row.state <> 'receiving' THEN
        IF embedded_spool IS NULL
           OR embedded_spool - 'durable_at_unix_ms'
                IS DISTINCT FROM requested_spool - 'durable_at_unix_ms' THEN
            RAISE EXCEPTION 'object-write durable spool replay changed its receipt'
                USING ERRCODE = '55000';
        END IF;
        IF attempt_row.accepted_sequence IS NOT NULL THEN
            SELECT authority.record::TEXT INTO authority_text
              FROM __CATS_SCHEMA_IDENT__.object_write_authorities authority
             WHERE authority.writer_authority_id=attempt_row.writer_authority_id;
        END IF;
        RETURN QUERY SELECT attempt_row.record::TEXT, authority_text,
            attempt_row.accepted_sequence IS NOT NULL;
        RETURN;
    END IF;
    now_ms := pg_catalog.floor(
        pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    durable_spool := pg_catalog.jsonb_set(
        requested_spool, '{durable_at_unix_ms}', pg_catalog.to_jsonb(now_ms), TRUE
    );
    updated_record := pg_catalog.jsonb_set(
        attempt_row.record, '{state}',
        pg_catalog.jsonb_build_object('kind', 'durable_spooled', 'spool', durable_spool),
        FALSE
    );
    UPDATE __CATS_SCHEMA_IDENT__.object_write_attempts attempt
       SET record=updated_record, state='durable_spooled',
           spool_id=durable_spool #>> '{spool_id}',
           spool_file_fsync_receipt_id=durable_spool #>> '{file_fsync_receipt_id}',
           spool_directory_fsync_receipt_id=
                durable_spool #>> '{directory_fsync_receipt_id}',
           spool_durable_at_unix_ms=now_ms
     WHERE attempt.request_id=requested_request_id AND attempt.state='receiving';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write receiving row changed while locked'
            USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT updated_record::TEXT, NULL::TEXT, FALSE;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_spool_durable_v1(
        TEXT,JSONB) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_accept_v1(
    requested_request_id TEXT
)
RETURNS TABLE(record_json TEXT, authority_json TEXT, accepted BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    parent_id TEXT;
    authority_row RECORD;
    attempt_row RECORD;
    conflicting_row RECORD;
    now_ms BIGINT;
    computed_rejection_kind TEXT;
    computed_rejection_receipt_id TEXT;
    updated_record JSONB;
    updated_authority JSONB;
    descriptor JSONB;
    computed_accepted_sequence BIGINT;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway' THEN
        RAISE EXCEPTION 'object-write gateway PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    SELECT attempt.writer_authority_id INTO parent_id
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.request_id=requested_request_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write attempt does not exist'
            USING ERRCODE = 'P0002';
    END IF;
    SELECT authority.* INTO authority_row
      FROM __CATS_SCHEMA_IDENT__.object_write_authorities authority
     WHERE authority.writer_authority_id=parent_id
     FOR UPDATE;
    SELECT attempt.* INTO attempt_row
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.request_id=requested_request_id
     FOR UPDATE;
    IF authority_row.writer_authority_id IS NULL OR attempt_row.request_id IS NULL THEN
        RAISE EXCEPTION 'object-write authority or attempt disappeared'
            USING ERRCODE = '55000';
    END IF;
    IF attempt_row.accepted_sequence IS NOT NULL THEN
        RETURN QUERY SELECT attempt_row.record::TEXT,
            authority_row.record::TEXT, TRUE;
        RETURN;
    END IF;
    IF attempt_row.state = 'rejected_before_accept' THEN
        RETURN QUERY SELECT attempt_row.record::TEXT, NULL::TEXT, FALSE;
        RETURN;
    END IF;
    IF attempt_row.state <> 'durable_spooled' THEN
        RAISE EXCEPTION 'object-write body is not durably spooled'
            USING ERRCODE = '55000';
    END IF;

    computed_rejection_kind := CASE WHEN authority_row.state <> 'open'
        THEN 'writer_closed' ELSE NULL END;
    IF computed_rejection_kind IS NULL THEN
        SELECT existing.* INTO conflicting_row
          FROM __CATS_SCHEMA_IDENT__.object_write_attempts existing
         WHERE existing.writer_authority_id=parent_id
           AND existing.object_key=attempt_row.object_key
           AND existing.accepted_sequence IS NOT NULL
         FOR UPDATE;
        IF FOUND THEN
            computed_rejection_kind := 'object_key_conflict';
        END IF;
    END IF;
    now_ms := pg_catalog.floor(
        pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    IF computed_rejection_kind IS NOT NULL THEN
        computed_rejection_receipt_id := 'owrej1_' ||
            pg_catalog.substr(requested_request_id, 8) || '_' ||
            computed_rejection_kind;
        updated_record := pg_catalog.jsonb_set(
            attempt_row.record, '{state}',
            pg_catalog.jsonb_build_object(
                'kind', 'rejected_before_accept',
                'spool', attempt_row.record #> '{state,spool}',
                'reason', computed_rejection_kind,
                'rejection_receipt_id', computed_rejection_receipt_id,
                'rejected_at_unix_ms', now_ms
            ), FALSE
        );
        UPDATE __CATS_SCHEMA_IDENT__.object_write_attempts attempt
           SET record=updated_record, state='rejected_before_accept',
               rejection_kind=computed_rejection_kind,
               rejection_receipt_id=computed_rejection_receipt_id,
               rejected_at_unix_ms=now_ms
         WHERE attempt.request_id=requested_request_id
           AND attempt.state='durable_spooled';
        RETURN QUERY SELECT updated_record::TEXT, NULL::TEXT, FALSE;
        RETURN;
    END IF;

    IF authority_row.max_accepted_sequence = 9223372036854775807 THEN
        RAISE EXCEPTION 'object-write accepted sequence is exhausted'
            USING ERRCODE = '55000';
    END IF;
    computed_accepted_sequence := authority_row.max_accepted_sequence + 1;
    descriptor := pg_catalog.jsonb_build_object(
        'writer_authority_id', attempt_row.record #> '{ingress,writer_authority_id}',
        'accepted_sequence', pg_catalog.to_jsonb(computed_accepted_sequence),
        'request_id', attempt_row.record #> '{ingress,request_id}',
        'credential', attempt_row.record #> '{ingress,credential}',
        'volume_id', attempt_row.record #> '{ingress,volume_id}',
        'key', attempt_row.record #> '{ingress,key}',
        'target', attempt_row.record #> '{ingress,target}',
        'content_sha256', attempt_row.record #> '{ingress,content_sha256}',
        'content_length', attempt_row.record #> '{ingress,content_length}',
        'qualification_fault', attempt_row.record #> '{ingress,qualification_fault}',
        'provider_attempt_id', 'owpa1_' ||
            pg_catalog.substr(requested_request_id, 8),
        'accepted_at_unix_ms', pg_catalog.to_jsonb(now_ms)
    );
    updated_record := pg_catalog.jsonb_build_object(
        'descriptor', descriptor,
        'state', pg_catalog.jsonb_build_object(
            'kind', 'accepted_spooled',
            'spool', attempt_row.record #> '{state,spool}'
        )
    );
    updated_authority := pg_catalog.jsonb_set(
        authority_row.record, '{max_accepted_sequence}',
        pg_catalog.to_jsonb(computed_accepted_sequence), FALSE
    );
    UPDATE __CATS_SCHEMA_IDENT__.object_write_authorities authority
       SET record=updated_authority,
           max_accepted_sequence=computed_accepted_sequence
     WHERE authority.writer_authority_id=parent_id
       AND authority.state='open'
       AND authority.max_accepted_sequence=authority_row.max_accepted_sequence;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write authority changed while accepting'
            USING ERRCODE = '55000';
    END IF;
    UPDATE __CATS_SCHEMA_IDENT__.object_write_attempts attempt
       SET record=updated_record, state='accepted_spooled',
           accepted_sequence=computed_accepted_sequence,
           accepted_at_unix_ms=now_ms,
           provider_attempt_id='owpa1_' ||
                pg_catalog.substr(requested_request_id, 8)
     WHERE attempt.request_id=requested_request_id
       AND attempt.state='durable_spooled';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write attempt changed while accepting'
            USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT updated_record::TEXT, updated_authority::TEXT, TRUE;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_accept_v1(TEXT) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_provider_issued_v1(
    requested_request_id TEXT
)
RETURNS TABLE(record_json TEXT, authority_json TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    parent_id TEXT;
    authority_row RECORD;
    attempt_row RECORD;
    now_ms BIGINT;
    updated_record JSONB;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway' THEN
        RAISE EXCEPTION 'object-write gateway PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    SELECT attempt.writer_authority_id INTO parent_id
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.request_id=requested_request_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write attempt does not exist'
            USING ERRCODE = 'P0002';
    END IF;
    SELECT authority.* INTO authority_row
      FROM __CATS_SCHEMA_IDENT__.object_write_authorities authority
     WHERE authority.writer_authority_id=parent_id
     FOR UPDATE;
    SELECT attempt.* INTO attempt_row
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.request_id=requested_request_id
     FOR UPDATE;
    IF authority_row.writer_authority_id IS NULL
       OR attempt_row.accepted_sequence IS NULL THEN
        RAISE EXCEPTION 'object-write request has not been accepted'
            USING ERRCODE = '55000';
    END IF;
    IF attempt_row.state <> 'accepted_spooled' THEN
        RETURN QUERY SELECT attempt_row.record::TEXT, authority_row.record::TEXT;
        RETURN;
    END IF;
    now_ms := pg_catalog.floor(
        pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    updated_record := pg_catalog.jsonb_set(
        attempt_row.record, '{state}',
        pg_catalog.jsonb_build_object(
            'kind', 'provider_issued',
            'spool', attempt_row.record #> '{state,spool}',
            'issued_at_unix_ms', now_ms
        ), FALSE
    );
    UPDATE __CATS_SCHEMA_IDENT__.object_write_attempts attempt
       SET record=updated_record, state='provider_issued',
           provider_issued_at_unix_ms=now_ms
     WHERE attempt.request_id=requested_request_id
       AND attempt.state='accepted_spooled';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write attempt changed before provider issue'
            USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT updated_record::TEXT, authority_row.record::TEXT;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_provider_issued_v1(TEXT) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_qualification_response_lost_v1(
    p_request_canonical BYTEA,
    p_successful_put_canonical BYTEA
)
RETURNS TABLE(
    found BOOLEAN,
    attempt_canonical BYTEA,
    authorization_canonical BYTEA,
    response_loss_canonical BYTEA
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    request_json JSONB;
    successful_put_json JSONB;
    request_text TEXT;
    successful_put_text TEXT;
    authorization_row RECORD;
    attempt_row RECORD;
    injected_at BIGINT;
    authorization_sha256 TEXT;
    injection_receipt_id TEXT;
    response_loss_text TEXT;
    response_loss_bytes BYTEA;
    response_loss_sha256 TEXT;
    descriptor_text TEXT;
    key_text TEXT;
    fault_text TEXT;
    spool_text TEXT;
    state_text TEXT;
    attempt_text TEXT;
    hash_input BYTEA;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway' THEN
        RAISE EXCEPTION 'object-write gateway PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF pg_catalog.octet_length(p_request_canonical) NOT BETWEEN 1 AND 16384
       OR (p_successful_put_canonical IS NOT NULL
           AND pg_catalog.octet_length(p_successful_put_canonical)
               NOT BETWEEN 1 AND 32768) THEN
        RAISE EXCEPTION 'object-write qualification canonical frame is invalid'
            USING ERRCODE = '22023';
    END IF;
    BEGIN
        request_json := pg_catalog.convert_from(p_request_canonical, 'UTF8')::JSONB;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'object-write qualification request is malformed'
            USING ERRCODE = '22023';
    END;
    IF pg_catalog.jsonb_typeof(request_json) <> 'object'
       OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(request_json)) <> 12
       OR request_json #>> '{version}' IS DISTINCT FROM '1'
       OR request_json #>> '{mutation_class}'
            IS DISTINCT FROM 'object_write_ambiguity'
       OR request_json #>> '{request_id}' !~ '^sha256:[0-9a-f]{64}$'
       OR pg_catalog.jsonb_typeof(request_json -> 'credential') IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*)
             FROM pg_catalog.jsonb_object_keys(request_json -> 'credential')) <> 2
       OR pg_catalog.jsonb_typeof(request_json -> 'fault') IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*)
             FROM pg_catalog.jsonb_object_keys(request_json -> 'fault')) <> 4
       OR pg_catalog.jsonb_typeof(request_json -> 'object_provider_scope')
            IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(
            request_json -> 'object_provider_scope')) <> 4
       OR request_json #>> '{provider_attempt_id}' !~ '^owpa1_[0-9a-f]{64}$'
       OR request_json #>> '{fault,kind}'
            IS DISTINCT FROM 'successful_put_response_loss'
       OR request_json #>> '{fault,fault_id}' !~ '^[0-9a-f]{32}$'
       OR request_json #>> '{fault,qualification_catalog_sha256}'
            !~ '^sha256:[0-9a-f]{64}$'
       OR request_json #>> '{content_sha256}' !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE((request_json #>> '{content_length}')::BIGINT, -1)
            NOT BETWEEN 0 AND 33554432 THEN
        RAISE EXCEPTION 'object-write qualification request is invalid'
            USING ERRCODE = '22023';
    END IF;
    request_text :=
        '{"version":1,"mutation_class":"object_write_ambiguity","request_id":' ||
        pg_catalog.to_json(request_json #>> '{request_id}')::TEXT ||
        ',"writer_authority_id":' ||
        pg_catalog.to_json(request_json #>> '{writer_authority_id}')::TEXT ||
        ',"credential":{"credential_id":' ||
        pg_catalog.to_json(request_json #>> '{credential,credential_id}')::TEXT ||
        ',"public_key_spki_sha256":' ||
        pg_catalog.to_json(request_json #>> '{credential,public_key_spki_sha256}')::TEXT ||
        '},"provider_attempt_id":' ||
        pg_catalog.to_json(request_json #>> '{provider_attempt_id}')::TEXT ||
        ',"fault":{"kind":"successful_put_response_loss","qualification_id":' ||
        pg_catalog.to_json(request_json #>> '{fault,qualification_id}')::TEXT ||
        ',"fault_id":' || pg_catalog.to_json(request_json #>> '{fault,fault_id}')::TEXT ||
        ',"qualification_catalog_sha256":' ||
        pg_catalog.to_json(
            request_json #>> '{fault,qualification_catalog_sha256}')::TEXT ||
        '},"object_provider_scope":{"provider":' ||
        pg_catalog.to_json(request_json #>> '{object_provider_scope,provider}')::TEXT ||
        ',"partition":' ||
        pg_catalog.to_json(request_json #>> '{object_provider_scope,partition}')::TEXT ||
        ',"account_id":' ||
        pg_catalog.to_json(request_json #>> '{object_provider_scope,account_id}')::TEXT ||
        ',"region":' ||
        pg_catalog.to_json(request_json #>> '{object_provider_scope,region}')::TEXT ||
        '},"object_store_scope_id":' ||
        pg_catalog.to_json(request_json #>> '{object_store_scope_id}')::TEXT ||
        ',"canonical_logical_key":' ||
        pg_catalog.to_json(request_json #>> '{canonical_logical_key}')::TEXT ||
        ',"content_sha256":' ||
        pg_catalog.to_json(request_json #>> '{content_sha256}')::TEXT ||
        ',"content_length":' || (request_json #>> '{content_length}') || '}';
    IF pg_catalog.convert_to(request_text, 'UTF8') IS DISTINCT FROM p_request_canonical THEN
        RAISE EXCEPTION 'object-write qualification request is not canonical'
            USING ERRCODE = '22023';
    END IF;

    -- Every replica uses this content-addressed request lock. The client
    -- acquires it in a preceding READ COMMITTED statement so a waiter takes a
    -- fresh snapshot after the winning transaction commits; this reentrant
    -- acquisition keeps direct routine calls serialized too.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        (('x' || pg_catalog.substr(pg_catalog.encode(pg_catalog.sha256(
            pg_catalog.convert_to(
                'cats.object-write-qualification-request-lock.v1' ||
                pg_catalog.chr(1) || (request_json #>> '{request_id}'),
                'UTF8'
            )
        ), 'hex'), 1, 16))::bit(64)::bigint)
    );

    IF p_successful_put_canonical IS NULL THEN
        SELECT attempt.* INTO attempt_row
          FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
         WHERE attempt.request_id=request_json #>> '{request_id}';
        IF NOT FOUND THEN
            RAISE EXCEPTION 'object-write qualification attempt does not exist'
                USING ERRCODE = 'P0002';
        END IF;
        IF attempt_row.qualification_response_loss_canonical IS NULL
           AND attempt_row.qualification_unproven_receipt_canonical IS NULL THEN
            RETURN QUERY SELECT FALSE, NULL::BYTEA, NULL::BYTEA, NULL::BYTEA;
            RETURN;
        END IF;
        IF attempt_row.qualification_request_canonical
                IS DISTINCT FROM p_request_canonical THEN
            RAISE EXCEPTION 'object-write qualification discovery changed its request'
                USING ERRCODE = '55000';
        END IF;
        IF attempt_row.qualification_response_loss_canonical IS NOT NULL THEN
            RETURN QUERY SELECT TRUE,
                attempt_row.qualification_response_lost_attempt_canonical,
                attempt_row.qualification_authorization_canonical,
                attempt_row.qualification_response_loss_canonical;
        ELSE
            IF attempt_row.state NOT IN (
                    'qualification_unproven_visible', 'spool_removed')
               OR attempt_row.qualification_unproven_attempt_canonical IS NULL THEN
                RAISE EXCEPTION 'object-write qualification resolution is partial'
                    USING ERRCODE = '55000';
            END IF;
            RETURN QUERY SELECT TRUE,
                attempt_row.qualification_unproven_attempt_canonical,
                NULL::BYTEA,
                NULL::BYTEA;
        END IF;
        RETURN;
    END IF;

    BEGIN
        successful_put_json :=
            pg_catalog.convert_from(p_successful_put_canonical, 'UTF8')::JSONB;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'object-write successful PUT evidence is malformed'
            USING ERRCODE = '22023';
    END;
    IF pg_catalog.jsonb_typeof(successful_put_json) <> 'object'
       OR (SELECT pg_catalog.count(*)
             FROM pg_catalog.jsonb_object_keys(successful_put_json)) <> 4
       OR successful_put_json #>> '{provider_attempt_id}'
            IS DISTINCT FROM request_json #>> '{provider_attempt_id}'
       OR pg_catalog.jsonb_typeof(successful_put_json -> 'put_receipt_id')
            IS DISTINCT FROM 'string'
       OR pg_catalog.octet_length(successful_put_json #>> '{put_receipt_id}')
            NOT BETWEEN 1 AND 512
       OR successful_put_json #>> '{put_receipt_id}' !~ '^[ -~]+$'
       OR pg_catalog.jsonb_typeof(successful_put_json -> 'provider_request')
            IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(
            successful_put_json -> 'provider_request')) <> 6
       OR pg_catalog.jsonb_typeof(
            successful_put_json #> '{provider_request,request_id}')
            IS DISTINCT FROM 'string'
       OR pg_catalog.octet_length(
            successful_put_json #>> '{provider_request,request_id}')
            NOT BETWEEN 1 AND 512
       OR successful_put_json #>> '{provider_request,request_id}' !~ '^[ -~]+$'
       OR successful_put_json #>> '{provider_request,content_sha256}'
            IS DISTINCT FROM request_json #>> '{content_sha256}'
       OR (successful_put_json #> '{provider_request,content_length}' <> 'null'::JSONB
           AND successful_put_json #>> '{provider_request,content_length}'
                IS DISTINCT FROM request_json #>> '{content_length}')
       OR (pg_catalog.jsonb_typeof(
                successful_put_json #> '{provider_request,extended_request_id}')
                IS DISTINCT FROM 'null'
           AND (pg_catalog.jsonb_typeof(
                    successful_put_json #> '{provider_request,extended_request_id}')
                    IS DISTINCT FROM 'string'
                OR pg_catalog.octet_length(successful_put_json #>>
                    '{provider_request,extended_request_id}') NOT BETWEEN 1 AND 512
                OR successful_put_json #>> '{provider_request,extended_request_id}'
                    !~ '^[ -~]+$'))
       OR (pg_catalog.jsonb_typeof(
                successful_put_json #> '{provider_request,entity_tag}')
                IS DISTINCT FROM 'null'
           AND (pg_catalog.jsonb_typeof(
                    successful_put_json #> '{provider_request,entity_tag}')
                    IS DISTINCT FROM 'string'
                OR pg_catalog.octet_length(successful_put_json #>>
                    '{provider_request,entity_tag}') NOT BETWEEN 1 AND 512
                OR successful_put_json #>> '{provider_request,entity_tag}'
                    !~ '^[ -~]+$'))
       OR (pg_catalog.jsonb_typeof(
                successful_put_json #> '{provider_request,version_id}')
                IS DISTINCT FROM 'null'
           AND (pg_catalog.jsonb_typeof(
                    successful_put_json #> '{provider_request,version_id}')
                    IS DISTINCT FROM 'string'
                OR pg_catalog.octet_length(successful_put_json #>>
                    '{provider_request,version_id}') NOT BETWEEN 1 AND 512
                OR successful_put_json #>> '{provider_request,version_id}'
                    !~ '^[ -~]+$'))
       OR COALESCE((successful_put_json #>> '{completed_at_unix_ms}')::BIGINT, -1) < 0 THEN
        RAISE EXCEPTION 'object-write successful PUT evidence is invalid'
            USING ERRCODE = '22023';
    END IF;
    successful_put_text :=
        '{"provider_attempt_id":' ||
        pg_catalog.to_json(successful_put_json #>> '{provider_attempt_id}')::TEXT ||
        ',"put_receipt_id":' ||
        pg_catalog.to_json(successful_put_json #>> '{put_receipt_id}')::TEXT ||
        ',"provider_request":{"request_id":' ||
        pg_catalog.to_json(successful_put_json #>> '{provider_request,request_id}')::TEXT ||
        ',"extended_request_id":' || CASE
            WHEN successful_put_json #> '{provider_request,extended_request_id}' = 'null'::JSONB
                THEN 'null'
            ELSE pg_catalog.to_json(
                successful_put_json #>> '{provider_request,extended_request_id}')::TEXT END ||
        ',"content_sha256":' ||
        pg_catalog.to_json(
            successful_put_json #>> '{provider_request,content_sha256}')::TEXT ||
        ',"content_length":' || CASE
            WHEN successful_put_json #> '{provider_request,content_length}' = 'null'::JSONB
                THEN 'null'
            ELSE successful_put_json #>> '{provider_request,content_length}' END ||
        ',"entity_tag":' || CASE
            WHEN successful_put_json #> '{provider_request,entity_tag}' = 'null'::JSONB
                THEN 'null'
            ELSE pg_catalog.to_json(
                successful_put_json #>> '{provider_request,entity_tag}')::TEXT END ||
        ',"version_id":' || CASE
            WHEN successful_put_json #> '{provider_request,version_id}' = 'null'::JSONB
                THEN 'null'
            ELSE pg_catalog.to_json(
                successful_put_json #>> '{provider_request,version_id}')::TEXT END ||
        '},"completed_at_unix_ms":' ||
        (successful_put_json #>> '{completed_at_unix_ms}') || '}';
    IF pg_catalog.convert_to(successful_put_text, 'UTF8')
            IS DISTINCT FROM p_successful_put_canonical THEN
        RAISE EXCEPTION 'object-write successful PUT evidence is not canonical'
            USING ERRCODE = '22023';
    END IF;

    -- Durable replay is independent of current E13 admission and therefore
    -- remains available after End/Close. Only a genuinely absent resolution
    -- is allowed to consult the current qualification singleton below.
    SELECT attempt.* INTO attempt_row
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.request_id=request_json #>> '{request_id}';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write qualification attempt does not exist'
            USING ERRCODE = 'P0002';
    END IF;
    IF attempt_row.qualification_response_loss_canonical IS NOT NULL THEN
        IF attempt_row.qualification_request_canonical
                IS DISTINCT FROM p_request_canonical
           OR attempt_row.qualification_successful_put_canonical
                IS DISTINCT FROM p_successful_put_canonical THEN
            RAISE EXCEPTION 'object-write qualification commit replay changed evidence'
                USING ERRCODE = '55000';
        END IF;
        RETURN QUERY SELECT TRUE,
            attempt_row.qualification_response_lost_attempt_canonical,
            attempt_row.qualification_authorization_canonical,
            attempt_row.qualification_response_loss_canonical;
        RETURN;
    ELSIF attempt_row.qualification_unproven_receipt_canonical IS NOT NULL THEN
        RAISE EXCEPTION 'object-write qualification already resolved as unproven visible'
            USING ERRCODE = '55000';
    END IF;

    SELECT * INTO authorization_row
      FROM __CATS_SCHEMA_IDENT__.control_object_write_gateway_qualification_lock_v1(
        p_request_canonical,
        1::BIGINT,
        'object_write_ambiguity'::TEXT,
        request_json #>> '{request_id}',
        request_json #>> '{writer_authority_id}',
        request_json #>> '{credential,credential_id}',
        request_json #>> '{credential,public_key_spki_sha256}',
        request_json #>> '{provider_attempt_id}',
        'successful_put_response_loss'::TEXT,
        request_json #>> '{fault,qualification_id}',
        request_json #>> '{fault,fault_id}',
        request_json #>> '{fault,qualification_catalog_sha256}',
        request_json #>> '{object_provider_scope,provider}',
        request_json #>> '{object_provider_scope,partition}',
        request_json #>> '{object_provider_scope,account_id}',
        request_json #>> '{object_provider_scope,region}',
        request_json #>> '{object_store_scope_id}',
        request_json #>> '{canonical_logical_key}',
        request_json #>> '{content_sha256}',
        (request_json #>> '{content_length}')::BIGINT
      );
    IF authorization_row.authorization_canonical IS NULL
       OR authorization_row.request_canonical IS DISTINCT FROM p_request_canonical THEN
        RAISE EXCEPTION 'object-write qualification authorization changed its request'
            USING ERRCODE = '55000';
    END IF;

    SELECT attempt.* INTO attempt_row
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.request_id=request_json #>> '{request_id}'
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write qualification attempt does not exist'
            USING ERRCODE = 'P0002';
    END IF;
    IF attempt_row.qualification_response_loss_canonical IS NOT NULL THEN
        IF attempt_row.qualification_request_canonical
                IS DISTINCT FROM p_request_canonical
           OR attempt_row.qualification_successful_put_canonical
                IS DISTINCT FROM p_successful_put_canonical
           OR attempt_row.qualification_authorization_canonical
                IS DISTINCT FROM authorization_row.authorization_canonical THEN
            RAISE EXCEPTION 'object-write qualification commit replay changed evidence'
                USING ERRCODE = '55000';
        END IF;
        RETURN QUERY SELECT TRUE,
            attempt_row.qualification_response_lost_attempt_canonical,
            attempt_row.qualification_authorization_canonical,
            attempt_row.qualification_response_loss_canonical;
        RETURN;
    END IF;
    IF attempt_row.state <> 'provider_issued'
       OR attempt_row.writer_authority_id
            IS DISTINCT FROM request_json #>> '{writer_authority_id}'
       OR attempt_row.credential_id
            IS DISTINCT FROM request_json #>> '{credential,credential_id}'
       OR attempt_row.provider_attempt_id
            IS DISTINCT FROM request_json #>> '{provider_attempt_id}'
       OR attempt_row.object_provider
            IS DISTINCT FROM request_json #>> '{object_provider_scope,provider}'
       OR attempt_row.object_partition
            IS DISTINCT FROM request_json #>> '{object_provider_scope,partition}'
       OR attempt_row.object_account_id
            IS DISTINCT FROM request_json #>> '{object_provider_scope,account_id}'
       OR attempt_row.object_region
            IS DISTINCT FROM request_json #>> '{object_provider_scope,region}'
       OR attempt_row.object_store_scope_id
            IS DISTINCT FROM request_json #>> '{object_store_scope_id}'
       OR attempt_row.object_key
            IS DISTINCT FROM request_json #>> '{canonical_logical_key}'
       OR attempt_row.content_sha256
            IS DISTINCT FROM request_json #>> '{content_sha256}'
       OR attempt_row.content_length
            IS DISTINCT FROM (request_json #>> '{content_length}')::BIGINT
       OR attempt_row.record #> '{descriptor,credential}'
            IS DISTINCT FROM request_json -> 'credential'
       OR attempt_row.record #> '{descriptor,qualification_fault}'
            IS DISTINCT FROM request_json -> 'fault' THEN
        RAISE EXCEPTION 'object-write qualification attempt changed before commit'
            USING ERRCODE = '55000';
    END IF;

    injected_at := pg_catalog.floor(
        pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    IF (successful_put_json #>> '{completed_at_unix_ms}')::BIGINT
            < authorization_row.authorized_at_unix_ms
       OR injected_at < (successful_put_json #>> '{completed_at_unix_ms}')::BIGINT
       OR injected_at >= authorization_row.qualification_expires_at_unix_ms THEN
        RAISE EXCEPTION 'object-write qualification expired around provider success'
            USING ERRCODE = '42501';
    END IF;
    hash_input :=
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to(
                'cats.object-write-qualification-authorization.v1', 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            authorization_row.authorization_canonical);
    authorization_sha256 := 'sha256:' ||
        pg_catalog.encode(pg_catalog.sha256(hash_input), 'hex');
    hash_input :=
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to(
                'cats.object-write-qualification-response-loss-injection.v1', 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.convert_to(authorization_sha256, 'UTF8')) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            p_successful_put_canonical) ||
        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
            pg_catalog.int8send(injected_at));
    injection_receipt_id := 'owqinj1_' ||
        pg_catalog.encode(pg_catalog.sha256(hash_input), 'hex');
    response_loss_text :=
        '{"version":1,"authorization":' ||
        pg_catalog.convert_from(authorization_row.authorization_canonical, 'UTF8') ||
        ',"successful_put":' || successful_put_text ||
        ',"injection_receipt_id":' ||
        pg_catalog.to_json(injection_receipt_id)::TEXT ||
        ',"injected_at_unix_ms":' || injected_at::TEXT || '}';
    response_loss_bytes := pg_catalog.convert_to(response_loss_text, 'UTF8');
    response_loss_sha256 := 'sha256:' ||
        pg_catalog.encode(pg_catalog.sha256(response_loss_bytes), 'hex');

    IF attempt_row.record #>> '{descriptor,key,kind}' = 'volume_data' THEN
        key_text := '{"kind":"volume_data","transaction_id":' ||
            pg_catalog.to_json(
                attempt_row.record #>> '{descriptor,key,transaction_id}')::TEXT ||
            ',"chunk_index":' ||
                (attempt_row.record #>> '{descriptor,key,chunk_index}') ||
            ',"object_kind":' || pg_catalog.to_json(
                attempt_row.record #>> '{descriptor,key,object_kind}')::TEXT || '}';
    ELSIF attempt_row.record #>> '{descriptor,key,kind}' = 'volume_map' THEN
        key_text := '{"kind":"volume_map"}';
    ELSIF attempt_row.record #>> '{descriptor,key,kind}' = 'volume_commit' THEN
        key_text := '{"kind":"volume_commit","generation":' ||
            (attempt_row.record #>> '{descriptor,key,generation}') ||
            ',"transaction_id":' || pg_catalog.to_json(
                attempt_row.record #>> '{descriptor,key,transaction_id}')::TEXT || '}';
    ELSE
        RAISE EXCEPTION 'object-write qualification key projection is corrupt'
            USING ERRCODE = '55000';
    END IF;
    fault_text := '{"kind":"successful_put_response_loss","qualification_id":' ||
        pg_catalog.to_json(request_json #>> '{fault,qualification_id}')::TEXT ||
        ',"fault_id":' ||
        pg_catalog.to_json(request_json #>> '{fault,fault_id}')::TEXT ||
        ',"qualification_catalog_sha256":' ||
        pg_catalog.to_json(
            request_json #>> '{fault,qualification_catalog_sha256}')::TEXT || '}';
    descriptor_text := '{"writer_authority_id":' ||
        pg_catalog.to_json(attempt_row.writer_authority_id)::TEXT ||
        ',"accepted_sequence":' || attempt_row.accepted_sequence::TEXT ||
        ',"request_id":' || pg_catalog.to_json(attempt_row.request_id)::TEXT ||
        ',"credential":{"credential_id":' ||
        pg_catalog.to_json(attempt_row.record #>> '{descriptor,credential,credential_id}')::TEXT ||
        ',"public_key_spki_sha256":' || pg_catalog.to_json(
            attempt_row.record #>> '{descriptor,credential,public_key_spki_sha256}')::TEXT ||
        '},"volume_id":' || pg_catalog.to_json(attempt_row.volume_id)::TEXT ||
        ',"key":' || key_text ||
        ',"target":{"object_provider_scope":{"provider":' ||
        pg_catalog.to_json(attempt_row.object_provider)::TEXT ||
        ',"partition":' || pg_catalog.to_json(attempt_row.object_partition)::TEXT ||
        ',"account_id":' || pg_catalog.to_json(attempt_row.object_account_id)::TEXT ||
        ',"region":' || pg_catalog.to_json(attempt_row.object_region)::TEXT ||
        '},"object_store_scope_id":' ||
        pg_catalog.to_json(attempt_row.object_store_scope_id)::TEXT ||
        ',"canonical_logical_key":' || pg_catalog.to_json(attempt_row.object_key)::TEXT ||
        '},"content_sha256":' || pg_catalog.to_json(attempt_row.content_sha256)::TEXT ||
        ',"content_length":' || attempt_row.content_length::TEXT ||
        ',"qualification_fault":' || fault_text ||
        ',"provider_attempt_id":' || pg_catalog.to_json(attempt_row.provider_attempt_id)::TEXT ||
        ',"accepted_at_unix_ms":' || attempt_row.accepted_at_unix_ms::TEXT || '}';
    spool_text := '{"spool_id":' || pg_catalog.to_json(attempt_row.spool_id)::TEXT ||
        ',"request_id":' || pg_catalog.to_json(attempt_row.request_id)::TEXT ||
        ',"content_sha256":' || pg_catalog.to_json(attempt_row.content_sha256)::TEXT ||
        ',"content_length":' || attempt_row.content_length::TEXT ||
        ',"file_fsync_receipt_id":' ||
        pg_catalog.to_json(attempt_row.spool_file_fsync_receipt_id)::TEXT ||
        ',"directory_fsync_receipt_id":' ||
        pg_catalog.to_json(attempt_row.spool_directory_fsync_receipt_id)::TEXT ||
        ',"durable_at_unix_ms":' || attempt_row.spool_durable_at_unix_ms::TEXT || '}';
    state_text := '{"kind":"qualification_response_lost","spool":' || spool_text ||
        ',"issued_at_unix_ms":' || attempt_row.provider_issued_at_unix_ms::TEXT ||
        ',"response_loss":' || response_loss_text || '}';
    attempt_text := '{"descriptor":' || descriptor_text || ',"state":' || state_text || '}';

    UPDATE __CATS_SCHEMA_IDENT__.object_write_attempts attempt
       SET record=pg_catalog.convert_from(
                pg_catalog.convert_to(attempt_text, 'UTF8'), 'UTF8')::JSONB,
           state='qualification_response_lost',
           qualification_request_canonical=p_request_canonical,
           qualification_authorization_canonical=
                authorization_row.authorization_canonical,
           qualification_successful_put_canonical=p_successful_put_canonical,
           qualification_response_loss_canonical=response_loss_bytes,
           qualification_response_lost_attempt_canonical=
                pg_catalog.convert_to(attempt_text, 'UTF8'),
           qualification_response_loss_sha256=response_loss_sha256,
           qualification_injection_receipt_id=injection_receipt_id,
           qualification_injected_at_unix_ms=injected_at
     WHERE attempt.request_id=attempt_row.request_id
       AND attempt.state='provider_issued';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write qualification attempt changed before receipt commit'
            USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT TRUE,
        pg_catalog.convert_to(attempt_text, 'UTF8'),
        authorization_row.authorization_canonical,
        response_loss_bytes;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_qualification_response_lost_v1(
        BYTEA,BYTEA) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_qualification_head_canonical_v1(
    value JSONB
)
RETURNS BYTEA
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    provider JSONB;
    conditional JSONB;
    conditional_provider JSONB;
    provider_text TEXT;
    conditional_provider_text TEXT;
    conditional_text TEXT;
    head_text TEXT;
BEGIN
    provider := value -> 'provider_request';
    conditional := value -> 'preceding_conditional_request';
    IF pg_catalog.jsonb_typeof(value) IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(value)) <> 5
       OR value #>> '{provider_attempt_id}' !~ '^owpa1_[0-9a-f]{64}$'
       OR pg_catalog.jsonb_typeof(value -> 'visibility_receipt_id')
            IS DISTINCT FROM 'string'
       OR pg_catalog.octet_length(value #>> '{visibility_receipt_id}') NOT BETWEEN 1 AND 512
       OR value #>> '{visibility_receipt_id}' !~ '^[ -~]+$'
       OR pg_catalog.jsonb_typeof(provider) IS DISTINCT FROM 'object'
       OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(provider)) <> 6
       OR pg_catalog.jsonb_typeof(provider -> 'request_id') IS DISTINCT FROM 'string'
       OR pg_catalog.octet_length(provider #>> '{request_id}') NOT BETWEEN 1 AND 512
       OR provider #>> '{request_id}' !~ '^[ -~]+$'
       OR provider #>> '{content_sha256}' !~ '^sha256:[0-9a-f]{64}$'
       OR pg_catalog.jsonb_typeof(provider -> 'content_length') IS DISTINCT FROM 'number'
       OR provider #>> '{content_length}' !~ '^(0|[1-9][0-9]{0,8})$'
       OR (provider #>> '{content_length}')::BIGINT NOT BETWEEN 0 AND 33554432
       OR (pg_catalog.jsonb_typeof(provider -> 'extended_request_id')
                IS DISTINCT FROM 'null'
           AND pg_catalog.jsonb_typeof(provider -> 'extended_request_id')
                IS DISTINCT FROM 'string')
       OR (pg_catalog.jsonb_typeof(provider -> 'entity_tag') IS DISTINCT FROM 'null'
           AND pg_catalog.jsonb_typeof(provider -> 'entity_tag') IS DISTINCT FROM 'string')
       OR (pg_catalog.jsonb_typeof(provider -> 'version_id') IS DISTINCT FROM 'null'
           AND pg_catalog.jsonb_typeof(provider -> 'version_id') IS DISTINCT FROM 'string')
       OR (provider -> 'extended_request_id' <> 'null'::JSONB
           AND (pg_catalog.octet_length(provider #>> '{extended_request_id}')
                    NOT BETWEEN 1 AND 512
                OR provider #>> '{extended_request_id}' !~ '^[ -~]+$'))
       OR (provider -> 'entity_tag' <> 'null'::JSONB
           AND (pg_catalog.octet_length(provider #>> '{entity_tag}') NOT BETWEEN 1 AND 512
                OR provider #>> '{entity_tag}' !~ '^[ -~]+$'))
       OR (provider -> 'version_id' <> 'null'::JSONB
           AND (pg_catalog.octet_length(provider #>> '{version_id}') NOT BETWEEN 1 AND 512
                OR provider #>> '{version_id}' !~ '^[ -~]+$'))
       OR pg_catalog.jsonb_typeof(value -> 'observed_at_unix_ms') IS DISTINCT FROM 'number'
       OR value #>> '{observed_at_unix_ms}' !~ '^(0|[1-9][0-9]{0,18})$' THEN
        RAISE EXCEPTION 'object-write qualification HEAD evidence is invalid'
            USING ERRCODE = '22023';
    END IF;
    provider_text := '{"request_id":' ||
        pg_catalog.to_json(provider #>> '{request_id}')::TEXT ||
        ',"extended_request_id":' || CASE
            WHEN provider -> 'extended_request_id' = 'null'::JSONB THEN 'null'
            ELSE pg_catalog.to_json(provider #>> '{extended_request_id}')::TEXT END ||
        ',"content_sha256":' ||
        pg_catalog.to_json(provider #>> '{content_sha256}')::TEXT ||
        ',"content_length":' || (provider #>> '{content_length}') ||
        ',"entity_tag":' || CASE
            WHEN provider -> 'entity_tag' = 'null'::JSONB THEN 'null'
            ELSE pg_catalog.to_json(provider #>> '{entity_tag}')::TEXT END ||
        ',"version_id":' || CASE
            WHEN provider -> 'version_id' = 'null'::JSONB THEN 'null'
            ELSE pg_catalog.to_json(provider #>> '{version_id}')::TEXT END || '}';

    IF conditional = 'null'::JSONB THEN
        conditional_text := 'null';
    ELSE
        conditional_provider := conditional -> 'provider_request';
        IF pg_catalog.jsonb_typeof(conditional) IS DISTINCT FROM 'object'
           OR (SELECT pg_catalog.count(*)
                 FROM pg_catalog.jsonb_object_keys(conditional)) <> 4
           OR conditional #>> '{provider_attempt_id}'
                IS DISTINCT FROM value #>> '{provider_attempt_id}'
           OR conditional #>> '{outcome}' IS DISTINCT FROM 'precondition_failed'
           OR pg_catalog.jsonb_typeof(conditional_provider) IS DISTINCT FROM 'object'
           OR (SELECT pg_catalog.count(*)
                 FROM pg_catalog.jsonb_object_keys(conditional_provider)) <> 6
           OR pg_catalog.jsonb_typeof(conditional_provider -> 'request_id')
                IS DISTINCT FROM 'string'
           OR pg_catalog.octet_length(conditional_provider #>> '{request_id}')
                NOT BETWEEN 1 AND 512
           OR conditional_provider #>> '{request_id}' !~ '^[ -~]+$'
           OR conditional_provider #>> '{request_id}'
                IS NOT DISTINCT FROM provider #>> '{request_id}'
           OR conditional_provider #>> '{content_sha256}'
                IS DISTINCT FROM provider #>> '{content_sha256}'
           OR (pg_catalog.jsonb_typeof(conditional_provider -> 'content_length')
                    IS DISTINCT FROM 'null'
               AND (pg_catalog.jsonb_typeof(
                        conditional_provider -> 'content_length')
                        IS DISTINCT FROM 'number'
                    OR conditional_provider #>> '{content_length}'
                        !~ '^(0|[1-9][0-9]{0,8})$'
                    OR (conditional_provider #>> '{content_length}')::BIGINT
                        NOT BETWEEN 0 AND 33554432
                    OR conditional_provider #>> '{content_length}'
                        IS DISTINCT FROM provider #>> '{content_length}'))
           OR (pg_catalog.jsonb_typeof(conditional_provider -> 'extended_request_id')
                    IS DISTINCT FROM 'null'
               AND pg_catalog.jsonb_typeof(conditional_provider -> 'extended_request_id')
                    IS DISTINCT FROM 'string')
           OR (pg_catalog.jsonb_typeof(conditional_provider -> 'entity_tag')
                    IS DISTINCT FROM 'null'
               AND pg_catalog.jsonb_typeof(conditional_provider -> 'entity_tag')
                    IS DISTINCT FROM 'string')
           OR (pg_catalog.jsonb_typeof(conditional_provider -> 'version_id')
                    IS DISTINCT FROM 'null'
               AND pg_catalog.jsonb_typeof(conditional_provider -> 'version_id')
                    IS DISTINCT FROM 'string')
           OR (conditional_provider -> 'extended_request_id' <> 'null'::JSONB
               AND (pg_catalog.octet_length(
                        conditional_provider #>> '{extended_request_id}')
                        NOT BETWEEN 1 AND 512
                    OR conditional_provider #>> '{extended_request_id}' !~ '^[ -~]+$'))
           OR (conditional_provider -> 'entity_tag' <> 'null'::JSONB
               AND (pg_catalog.octet_length(conditional_provider #>> '{entity_tag}')
                        NOT BETWEEN 1 AND 512
                    OR conditional_provider #>> '{entity_tag}' !~ '^[ -~]+$'))
           OR (conditional_provider -> 'version_id' <> 'null'::JSONB
               AND (pg_catalog.octet_length(conditional_provider #>> '{version_id}')
                        NOT BETWEEN 1 AND 512
                    OR conditional_provider #>> '{version_id}' !~ '^[ -~]+$'))
           OR pg_catalog.jsonb_typeof(conditional -> 'observed_at_unix_ms')
                IS DISTINCT FROM 'number'
           OR conditional #>> '{observed_at_unix_ms}' !~ '^(0|[1-9][0-9]{0,18})$'
           OR (conditional #>> '{observed_at_unix_ms}')::BIGINT
                > (value #>> '{observed_at_unix_ms}')::BIGINT THEN
            RAISE EXCEPTION 'object-write conditional request evidence is invalid'
                USING ERRCODE = '22023';
        END IF;
        conditional_provider_text := '{"request_id":' ||
            pg_catalog.to_json(conditional_provider #>> '{request_id}')::TEXT ||
            ',"extended_request_id":' || CASE
                WHEN conditional_provider -> 'extended_request_id' = 'null'::JSONB
                    THEN 'null'
                ELSE pg_catalog.to_json(
                    conditional_provider #>> '{extended_request_id}')::TEXT END ||
            ',"content_sha256":' || pg_catalog.to_json(
                conditional_provider #>> '{content_sha256}')::TEXT ||
            ',"content_length":' || CASE
                WHEN conditional_provider -> 'content_length' = 'null'::JSONB
                    THEN 'null'
                ELSE conditional_provider #>> '{content_length}' END ||
            ',"entity_tag":' || CASE
                WHEN conditional_provider -> 'entity_tag' = 'null'::JSONB THEN 'null'
                ELSE pg_catalog.to_json(
                    conditional_provider #>> '{entity_tag}')::TEXT END ||
            ',"version_id":' || CASE
                WHEN conditional_provider -> 'version_id' = 'null'::JSONB THEN 'null'
                ELSE pg_catalog.to_json(
                    conditional_provider #>> '{version_id}')::TEXT END || '}';
        conditional_text := '{"provider_attempt_id":' || pg_catalog.to_json(
                conditional #>> '{provider_attempt_id}')::TEXT ||
            ',"outcome":"precondition_failed","provider_request":' ||
            conditional_provider_text || ',"observed_at_unix_ms":' ||
            (conditional #>> '{observed_at_unix_ms}') || '}';
    END IF;
    head_text := '{"provider_attempt_id":' ||
        pg_catalog.to_json(value #>> '{provider_attempt_id}')::TEXT ||
        ',"visibility_receipt_id":' ||
        pg_catalog.to_json(value #>> '{visibility_receipt_id}')::TEXT ||
        ',"preceding_conditional_request":' || conditional_text ||
        ',"provider_request":' || provider_text ||
        ',"observed_at_unix_ms":' || (value #>> '{observed_at_unix_ms}') || '}';
    RETURN pg_catalog.convert_to(head_text, 'UTF8');
EXCEPTION
    WHEN invalid_text_representation OR numeric_value_out_of_range THEN
        RAISE EXCEPTION 'object-write qualification HEAD number is invalid'
            USING ERRCODE = '22023';
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_qualification_head_canonical_v1(JSONB)
    FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_terminal_v1(
    requested_request_id TEXT,
    requested_outcome_canonical BYTEA
)
RETURNS TABLE(record_json TEXT, authority_json TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    requested_outcome JSONB;
    outcome_text TEXT;
    parent_id TEXT;
    authority_row RECORD;
    attempt_row RECORD;
    prefix_row RECORD;
    terminal_kind TEXT;
    terminal_at BIGINT;
    expected_state TEXT;
    qualified_success BOOLEAN;
    response_loss_json JSONB;
    head_canonical BYTEA;
    ambiguity_canonical BYTEA;
    unproven_intent BOOLEAN := FALSE;
    unproven_source TEXT;
    sealed_json JSONB;
    ingress_json JSONB;
    request_json JSONB;
    sealed_text TEXT;
    sealed_canonical BYTEA;
    ingress_text TEXT;
    request_text TEXT;
    key_text TEXT;
    fault_text TEXT;
    descriptor_text TEXT;
    head_text TEXT;
    intent_text TEXT;
    receipt_text TEXT;
    receipt_canonical BYTEA;
    resolution_receipt_id TEXT;
    attempt_text TEXT;
    spool_text TEXT;
    state_text TEXT;
    authorization_row RECORD;
    authorization_sha256 TEXT;
    ambiguity_sha256 TEXT;
    updated_record JSONB;
    updated_authority JSONB;
    prefix_sequence BIGINT;
    prefix_sha256 TEXT;
    expected_sequence BIGINT;
    hash_input BYTEA;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway' THEN
        RAISE EXCEPTION 'object-write gateway PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF pg_catalog.octet_length(requested_outcome_canonical) NOT BETWEEN 1 AND 65536 THEN
        RAISE EXCEPTION 'object-write terminal outcome frame is invalid'
            USING ERRCODE = '22023';
    END IF;
    BEGIN
        requested_outcome :=
            pg_catalog.convert_from(requested_outcome_canonical, 'UTF8')::JSONB;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'object-write terminal outcome is malformed'
            USING ERRCODE = '22023';
    END;
    IF pg_catalog.jsonb_typeof(requested_outcome) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'object-write terminal outcome is not an object'
            USING ERRCODE = '22023';
    END IF;
    terminal_kind := requested_outcome #>> '{kind}';
    unproven_intent := terminal_kind = 'qualification_unproven_visible_intent';
    IF unproven_intent THEN
        IF requested_outcome #>> '{sealed_request,authorization_request,request_id}'
                IS DISTINCT FROM requested_request_id
           OR requested_request_id !~ '^sha256:[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'object-write unproven intent changed its request'
                USING ERRCODE = '22023';
        END IF;
        PERFORM pg_catalog.pg_advisory_xact_lock(
            (('x' || pg_catalog.substr(pg_catalog.encode(pg_catalog.sha256(
                pg_catalog.convert_to(
                    'cats.object-write-qualification-request-lock.v1' ||
                    pg_catalog.chr(1) || requested_request_id,
                    'UTF8'
                )
            ), 'hex'), 1, 16))::bit(64)::bigint)
        );
    END IF;

    SELECT attempt.writer_authority_id INTO parent_id
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.request_id=requested_request_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write attempt does not exist'
            USING ERRCODE = 'P0002';
    END IF;
    SELECT authority.* INTO authority_row
      FROM __CATS_SCHEMA_IDENT__.object_write_authorities authority
     WHERE authority.writer_authority_id=parent_id
     FOR UPDATE;
    SELECT attempt.* INTO attempt_row
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.request_id=requested_request_id
     FOR UPDATE;
    IF authority_row.writer_authority_id IS NULL
       OR attempt_row.accepted_sequence IS NULL THEN
        RAISE EXCEPTION 'object-write request has not been accepted'
            USING ERRCODE = '55000';
    END IF;
    IF attempt_row.state IN (
        'terminal_visible','permanent','qualification_unproven_visible','spool_removed'
    ) THEN
        IF unproven_intent
           AND attempt_row.terminal_kind = 'qualification_unproven_visible'
           AND attempt_row.qualification_unproven_intent_canonical
                IS NOT DISTINCT FROM requested_outcome_canonical THEN
            RETURN QUERY SELECT attempt_row.record::TEXT, authority_row.record::TEXT;
            RETURN;
        ELSIF attempt_row.record #> '{state,outcome}' IS DISTINCT FROM requested_outcome THEN
            RAISE EXCEPTION 'object-write terminal replay changed its outcome'
                USING ERRCODE = '55000';
        END IF;
        RETURN QUERY SELECT attempt_row.record::TEXT, authority_row.record::TEXT;
        RETURN;
    END IF;

    BEGIN
        IF terminal_kind = 'succeeded_visible' THEN
            IF (SELECT pg_catalog.count(*)
                  FROM pg_catalog.jsonb_object_keys(requested_outcome)) <> 6
               OR pg_catalog.jsonb_typeof(requested_outcome -> 'put_receipt_id')
                    IS DISTINCT FROM 'string'
               OR pg_catalog.octet_length(requested_outcome #>> '{put_receipt_id}')
                    NOT BETWEEN 1 AND 512
               OR requested_outcome #>> '{put_receipt_id}' !~ '^[ -~]+$'
               OR pg_catalog.jsonb_typeof(
                    requested_outcome -> 'put_completed_at_unix_ms')
                    IS DISTINCT FROM 'number'
               OR requested_outcome #>> '{put_completed_at_unix_ms}'
                    !~ '^(0|[1-9][0-9]{0,18})$'
               OR pg_catalog.jsonb_typeof(requested_outcome -> 'visibility_receipt_id')
                    IS DISTINCT FROM 'string'
               OR pg_catalog.octet_length(requested_outcome #>> '{visibility_receipt_id}')
                    NOT BETWEEN 1 AND 512
               OR requested_outcome #>> '{visibility_receipt_id}' !~ '^[ -~]+$'
               OR pg_catalog.jsonb_typeof(requested_outcome -> 'visible_at_unix_ms')
                    IS DISTINCT FROM 'number'
               OR requested_outcome #>> '{visible_at_unix_ms}'
                    !~ '^(0|[1-9][0-9]{0,18})$' THEN
                RAISE EXCEPTION 'object-write success terminal outcome is invalid'
                    USING ERRCODE = '22023';
            END IF;
            terminal_at := (requested_outcome #>> '{visible_at_unix_ms}')::BIGINT;
            IF terminal_at < (requested_outcome #>> '{put_completed_at_unix_ms}')::BIGINT THEN
                RAISE EXCEPTION 'object-write success visibility precedes PUT'
                    USING ERRCODE = '22023';
            END IF;
            qualified_success := requested_outcome -> 'qualification_ambiguity'
                IS DISTINCT FROM 'null'::JSONB;
            IF qualified_success THEN
                response_loss_json := pg_catalog.convert_from(
                    attempt_row.qualification_response_loss_canonical, 'UTF8')::JSONB;
                IF attempt_row.state <> 'qualification_response_lost'
                   OR attempt_row.record #> '{descriptor,qualification_fault}' = 'null'::JSONB
                   OR attempt_row.qualification_response_loss_canonical IS NULL
                   OR pg_catalog.jsonb_typeof(
                        requested_outcome -> 'qualification_ambiguity')
                        IS DISTINCT FROM 'object'
                   OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(
                        requested_outcome -> 'qualification_ambiguity')) <> 3
                   OR requested_outcome #>> '{qualification_ambiguity,version}'
                        IS DISTINCT FROM '1'
                   OR requested_outcome #> '{qualification_ambiguity,response_loss}'
                        IS DISTINCT FROM response_loss_json
                   OR requested_outcome #>> '{put_receipt_id}' IS DISTINCT FROM
                        response_loss_json #>> '{successful_put,put_receipt_id}'
                   OR requested_outcome #>> '{put_completed_at_unix_ms}' IS DISTINCT FROM
                        response_loss_json #>> '{successful_put,completed_at_unix_ms}'
                   OR requested_outcome #>> '{visibility_receipt_id}' IS DISTINCT FROM
                        requested_outcome #>>
                            '{qualification_ambiguity,head,visibility_receipt_id}'
                   OR requested_outcome #>> '{visible_at_unix_ms}' IS DISTINCT FROM
                        requested_outcome #>>
                            '{qualification_ambiguity,head,observed_at_unix_ms}' THEN
                    RAISE EXCEPTION 'object-write qualified success changed response-loss evidence'
                        USING ERRCODE = '55000';
                END IF;
                head_canonical :=
                    __CATS_SCHEMA_IDENT__.control_object_write_gateway_qualification_head_canonical_v1(
                        requested_outcome #> '{qualification_ambiguity,head}');
                IF requested_outcome #>> '{qualification_ambiguity,head,provider_attempt_id}'
                        IS DISTINCT FROM attempt_row.provider_attempt_id
                   OR requested_outcome #>>
                        '{qualification_ambiguity,head,provider_request,content_sha256}'
                        IS DISTINCT FROM attempt_row.content_sha256
                   OR requested_outcome #>>
                        '{qualification_ambiguity,head,provider_request,content_length}'
                        IS DISTINCT FROM attempt_row.content_length::TEXT
                   OR requested_outcome #>
                        '{qualification_ambiguity,head,preceding_conditional_request}'
                        IS DISTINCT FROM 'null'::JSONB
                   OR requested_outcome #>>
                        '{qualification_ambiguity,head,provider_request,request_id}'
                        IS NOT DISTINCT FROM response_loss_json #>>
                            '{successful_put,provider_request,request_id}'
                   OR (requested_outcome #>>
                        '{qualification_ambiguity,head,observed_at_unix_ms}')::BIGINT
                        < (response_loss_json #>> '{injected_at_unix_ms}')::BIGINT
                   OR requested_outcome #>>
                        '{qualification_ambiguity,head,visibility_receipt_id}'
                        IS NOT DISTINCT FROM response_loss_json #>>
                            '{successful_put,put_receipt_id}'
                   OR (response_loss_json #>
                            '{successful_put,provider_request,entity_tag}'
                            IS DISTINCT FROM 'null'::JSONB
                       AND requested_outcome #>>
                            '{qualification_ambiguity,head,provider_request,entity_tag}'
                            IS DISTINCT FROM response_loss_json #>>
                                '{successful_put,provider_request,entity_tag}')
                   OR (response_loss_json #>
                            '{successful_put,provider_request,version_id}'
                            IS DISTINCT FROM 'null'::JSONB
                       AND requested_outcome #>>
                            '{qualification_ambiguity,head,provider_request,version_id}'
                            IS DISTINCT FROM response_loss_json #>>
                                '{successful_put,provider_request,version_id}') THEN
                    RAISE EXCEPTION 'object-write qualified HEAD changed the issued descriptor'
                        USING ERRCODE = '55000';
                END IF;
                ambiguity_canonical := pg_catalog.convert_to(
                    '{"version":1,"response_loss":' || pg_catalog.convert_from(
                        attempt_row.qualification_response_loss_canonical, 'UTF8') ||
                    ',"head":' || pg_catalog.convert_from(head_canonical, 'UTF8') || '}',
                    'UTF8');
                outcome_text := '{"kind":"succeeded_visible","put_receipt_id":' ||
                    pg_catalog.to_json(requested_outcome #>> '{put_receipt_id}')::TEXT ||
                    ',"put_completed_at_unix_ms":' ||
                    (requested_outcome #>> '{put_completed_at_unix_ms}') ||
                    ',"visibility_receipt_id":' || pg_catalog.to_json(
                        requested_outcome #>> '{visibility_receipt_id}')::TEXT ||
                    ',"visible_at_unix_ms":' ||
                    (requested_outcome #>> '{visible_at_unix_ms}') ||
                    ',"qualification_ambiguity":' ||
                    pg_catalog.convert_from(ambiguity_canonical, 'UTF8') || '}';
                expected_state := 'qualification_response_lost';
            ELSE
                IF requested_outcome -> 'qualification_ambiguity'
                        IS DISTINCT FROM 'null'::JSONB
                   OR attempt_row.state <> 'provider_issued'
                   OR attempt_row.record #> '{descriptor,qualification_fault}'
                        IS DISTINCT FROM 'null'::JSONB THEN
                    RAISE EXCEPTION 'ordinary object-write success crossed qualification state'
                        USING ERRCODE = '55000';
                END IF;
                outcome_text := '{"kind":"succeeded_visible","put_receipt_id":' ||
                    pg_catalog.to_json(requested_outcome #>> '{put_receipt_id}')::TEXT ||
                    ',"put_completed_at_unix_ms":' ||
                    (requested_outcome #>> '{put_completed_at_unix_ms}') ||
                    ',"visibility_receipt_id":' || pg_catalog.to_json(
                        requested_outcome #>> '{visibility_receipt_id}')::TEXT ||
                    ',"visible_at_unix_ms":' ||
                    (requested_outcome #>> '{visible_at_unix_ms}') ||
                    ',"qualification_ambiguity":null}';
                expected_state := 'provider_issued';
            END IF;
        ELSIF terminal_kind = 'permanently_failed' THEN
            IF (SELECT pg_catalog.count(*)
                  FROM pg_catalog.jsonb_object_keys(requested_outcome)) <> 3
               OR attempt_row.state <> 'provider_issued'
               OR attempt_row.record #> '{descriptor,qualification_fault}'
                    IS DISTINCT FROM 'null'::JSONB
               OR pg_catalog.jsonb_typeof(requested_outcome -> 'failure_receipt_id')
                    IS DISTINCT FROM 'string'
               OR pg_catalog.octet_length(requested_outcome #>> '{failure_receipt_id}')
                    NOT BETWEEN 1 AND 512
               OR requested_outcome #>> '{failure_receipt_id}' !~ '^[ -~]+$'
               OR pg_catalog.jsonb_typeof(requested_outcome -> 'failed_at_unix_ms')
                    IS DISTINCT FROM 'number'
               OR requested_outcome #>> '{failed_at_unix_ms}'
                    !~ '^(0|[1-9][0-9]{0,18})$' THEN
                RAISE EXCEPTION 'object-write failure terminal outcome is invalid'
                    USING ERRCODE = '22023';
            END IF;
            terminal_at := (requested_outcome #>> '{failed_at_unix_ms}')::BIGINT;
            outcome_text := '{"kind":"permanently_failed","failure_receipt_id":' ||
                pg_catalog.to_json(requested_outcome #>> '{failure_receipt_id}')::TEXT ||
                ',"failed_at_unix_ms":' ||
                (requested_outcome #>> '{failed_at_unix_ms}') || '}';
            expected_state := 'provider_issued';
        ELSIF unproven_intent THEN
            sealed_json := requested_outcome -> 'sealed_request';
            ingress_json := sealed_json -> 'ingress_descriptor';
            request_json := sealed_json -> 'authorization_request';
            unproven_source := requested_outcome #>> '{source}';
            IF (SELECT pg_catalog.count(*)
                  FROM pg_catalog.jsonb_object_keys(requested_outcome)) <> 4
               OR unproven_source NOT IN (
                    'issued_visibility', 'authorized_precondition')
               OR pg_catalog.jsonb_typeof(sealed_json) IS DISTINCT FROM 'object'
               OR (SELECT pg_catalog.count(*)
                     FROM pg_catalog.jsonb_object_keys(sealed_json)) <> 6
               OR pg_catalog.jsonb_typeof(ingress_json) IS DISTINCT FROM 'object'
               OR (SELECT pg_catalog.count(*)
                     FROM pg_catalog.jsonb_object_keys(ingress_json)) <> 6
               OR pg_catalog.jsonb_typeof(request_json) IS DISTINCT FROM 'object'
               OR (SELECT pg_catalog.count(*)
                     FROM pg_catalog.jsonb_object_keys(request_json)) <> 12
               OR sealed_json #>> '{version}' IS DISTINCT FROM '1'
               OR ingress_json #>> '{version}' IS DISTINCT FROM '1'
               OR attempt_row.state <> 'provider_issued'
               OR attempt_row.record #> '{descriptor,qualification_fault}' IS NULL
               OR attempt_row.record #> '{descriptor,qualification_fault}' = 'null'::JSONB
               OR attempt_row.qualification_response_loss_canonical IS NOT NULL
               OR attempt_row.qualification_unproven_receipt_canonical IS NOT NULL
               OR sealed_json #>> '{accepted_sequence}'
                    IS DISTINCT FROM attempt_row.accepted_sequence::TEXT
               OR sealed_json #>> '{accepted_at_unix_ms}'
                    IS DISTINCT FROM attempt_row.accepted_at_unix_ms::TEXT
               OR sealed_json #>> '{issued_at_unix_ms}'
                    IS DISTINCT FROM attempt_row.provider_issued_at_unix_ms::TEXT
               OR ingress_json #>> '{volume_id}' IS DISTINCT FROM attempt_row.volume_id
               OR ingress_json -> 'key'
                    IS DISTINCT FROM attempt_row.record #> '{descriptor,key}'
               OR ingress_json #>> '{content_sha256}'
                    IS DISTINCT FROM attempt_row.content_sha256
               OR ingress_json #>> '{content_length}'
                    IS DISTINCT FROM attempt_row.content_length::TEXT
               OR ingress_json -> 'qualification_fault'
                    IS DISTINCT FROM attempt_row.record #> '{descriptor,qualification_fault}'
               OR request_json #>> '{request_id}' IS DISTINCT FROM attempt_row.request_id
               OR request_json #>> '{writer_authority_id}'
                    IS DISTINCT FROM attempt_row.writer_authority_id
               OR request_json -> 'credential'
                    IS DISTINCT FROM attempt_row.record #> '{descriptor,credential}'
               OR request_json #>> '{provider_attempt_id}'
                    IS DISTINCT FROM attempt_row.provider_attempt_id
               OR request_json -> 'fault'
                    IS DISTINCT FROM attempt_row.record #> '{descriptor,qualification_fault}'
               OR request_json #>> '{object_provider_scope,provider}'
                    IS DISTINCT FROM attempt_row.object_provider
               OR request_json #>> '{object_provider_scope,partition}'
                    IS DISTINCT FROM attempt_row.object_partition
               OR request_json #>> '{object_provider_scope,account_id}'
                    IS DISTINCT FROM attempt_row.object_account_id
               OR request_json #>> '{object_provider_scope,region}'
                    IS DISTINCT FROM attempt_row.object_region
               OR request_json #>> '{object_store_scope_id}'
                    IS DISTINCT FROM attempt_row.object_store_scope_id
               OR request_json #>> '{canonical_logical_key}'
                    IS DISTINCT FROM attempt_row.object_key
               OR request_json #>> '{content_sha256}'
                    IS DISTINCT FROM attempt_row.content_sha256
               OR request_json #>> '{content_length}'
                    IS DISTINCT FROM attempt_row.content_length::TEXT THEN
                RAISE EXCEPTION 'object-write unproven intent changed the sealed request'
                    USING ERRCODE = '55000';
            END IF;

            IF attempt_row.record #>> '{descriptor,key,kind}' = 'volume_data' THEN
                key_text := '{"kind":"volume_data","transaction_id":' ||
                    pg_catalog.to_json(
                        attempt_row.record #>> '{descriptor,key,transaction_id}')::TEXT ||
                    ',"chunk_index":' ||
                    (attempt_row.record #>> '{descriptor,key,chunk_index}') ||
                    ',"object_kind":' || pg_catalog.to_json(
                        attempt_row.record #>> '{descriptor,key,object_kind}')::TEXT || '}';
            ELSIF attempt_row.record #>> '{descriptor,key,kind}' = 'volume_map' THEN
                key_text := '{"kind":"volume_map"}';
            ELSIF attempt_row.record #>> '{descriptor,key,kind}' = 'volume_commit' THEN
                key_text := '{"kind":"volume_commit","generation":' ||
                    (attempt_row.record #>> '{descriptor,key,generation}') ||
                    ',"transaction_id":' || pg_catalog.to_json(
                        attempt_row.record #>> '{descriptor,key,transaction_id}')::TEXT || '}';
            ELSE
                RAISE EXCEPTION 'object-write unproven key projection is corrupt'
                    USING ERRCODE = '55000';
            END IF;
            fault_text := '{"kind":"successful_put_response_loss","qualification_id":' ||
                pg_catalog.to_json(
                    attempt_row.record #>> '{descriptor,qualification_fault,qualification_id}')::TEXT ||
                ',"fault_id":' || pg_catalog.to_json(
                    attempt_row.record #>> '{descriptor,qualification_fault,fault_id}')::TEXT ||
                ',"qualification_catalog_sha256":' || pg_catalog.to_json(
                    attempt_row.record #>>
                        '{descriptor,qualification_fault,qualification_catalog_sha256}')::TEXT ||
                '}';
            request_text :=
                '{"version":1,"mutation_class":"object_write_ambiguity","request_id":' ||
                pg_catalog.to_json(attempt_row.request_id)::TEXT ||
                ',"writer_authority_id":' ||
                pg_catalog.to_json(attempt_row.writer_authority_id)::TEXT ||
                ',"credential":{"credential_id":' || pg_catalog.to_json(
                    attempt_row.record #>> '{descriptor,credential,credential_id}')::TEXT ||
                ',"public_key_spki_sha256":' || pg_catalog.to_json(
                    attempt_row.record #>>
                        '{descriptor,credential,public_key_spki_sha256}')::TEXT ||
                '},"provider_attempt_id":' ||
                pg_catalog.to_json(attempt_row.provider_attempt_id)::TEXT ||
                ',"fault":' || fault_text ||
                ',"object_provider_scope":{"provider":' ||
                pg_catalog.to_json(attempt_row.object_provider)::TEXT ||
                ',"partition":' || pg_catalog.to_json(attempt_row.object_partition)::TEXT ||
                ',"account_id":' || pg_catalog.to_json(attempt_row.object_account_id)::TEXT ||
                ',"region":' || pg_catalog.to_json(attempt_row.object_region)::TEXT ||
                '},"object_store_scope_id":' ||
                pg_catalog.to_json(attempt_row.object_store_scope_id)::TEXT ||
                ',"canonical_logical_key":' || pg_catalog.to_json(attempt_row.object_key)::TEXT ||
                ',"content_sha256":' || pg_catalog.to_json(attempt_row.content_sha256)::TEXT ||
                ',"content_length":' || attempt_row.content_length::TEXT || '}';
            IF pg_catalog.convert_from(pg_catalog.convert_to(request_text, 'UTF8'), 'UTF8')::JSONB
                    IS DISTINCT FROM request_json THEN
                RAISE EXCEPTION 'object-write unproven authorization request is not exact'
                    USING ERRCODE = '55000';
            END IF;
            ingress_text := '{"version":1,"volume_id":' ||
                pg_catalog.to_json(attempt_row.volume_id)::TEXT ||
                ',"key":' || key_text ||
                ',"content_sha256":' || pg_catalog.to_json(attempt_row.content_sha256)::TEXT ||
                ',"content_length":' || attempt_row.content_length::TEXT ||
                ',"qualification_fault":' || fault_text || '}';
            sealed_text := '{"version":1,"accepted_sequence":' ||
                attempt_row.accepted_sequence::TEXT ||
                ',"ingress_descriptor":' || ingress_text ||
                ',"authorization_request":' || request_text ||
                ',"accepted_at_unix_ms":' || attempt_row.accepted_at_unix_ms::TEXT ||
                ',"issued_at_unix_ms":' || attempt_row.provider_issued_at_unix_ms::TEXT || '}';
            sealed_canonical := pg_catalog.convert_to(sealed_text, 'UTF8');
            IF pg_catalog.convert_from(sealed_canonical, 'UTF8')::JSONB
                    IS DISTINCT FROM sealed_json THEN
                RAISE EXCEPTION 'object-write unproven sealed request is not canonical'
                    USING ERRCODE = '55000';
            END IF;
            head_canonical :=
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_qualification_head_canonical_v1(
                    requested_outcome -> 'head_evidence');
            head_text := pg_catalog.convert_from(head_canonical, 'UTF8');
            intent_text := '{"kind":"qualification_unproven_visible_intent","source":' ||
                pg_catalog.to_json(unproven_source)::TEXT ||
                ',"sealed_request":' || sealed_text ||
                ',"head_evidence":' || head_text || '}';
            IF pg_catalog.convert_to(intent_text, 'UTF8')
                    IS DISTINCT FROM requested_outcome_canonical THEN
                RAISE EXCEPTION 'object-write unproven intent is not canonical'
                    USING ERRCODE = '22023';
            END IF;
            IF requested_outcome #>> '{head_evidence,provider_attempt_id}'
                    IS DISTINCT FROM attempt_row.provider_attempt_id
               OR requested_outcome #>> '{head_evidence,provider_request,content_sha256}'
                    IS DISTINCT FROM attempt_row.content_sha256
               OR requested_outcome #>> '{head_evidence,provider_request,content_length}'
                    IS DISTINCT FROM attempt_row.content_length::TEXT
               OR (requested_outcome #>> '{head_evidence,observed_at_unix_ms}')::BIGINT
                    < attempt_row.provider_issued_at_unix_ms
               OR (requested_outcome #> '{head_evidence,preceding_conditional_request}'
                        IS DISTINCT FROM 'null'::JSONB
                   AND (requested_outcome #>>
                        '{head_evidence,preceding_conditional_request,observed_at_unix_ms}')::BIGINT
                        < attempt_row.provider_issued_at_unix_ms)
               OR (unproven_source = 'authorized_precondition'
                   AND requested_outcome #> '{head_evidence,preceding_conditional_request}'
                        IS NOT DISTINCT FROM 'null'::JSONB) THEN
                RAISE EXCEPTION 'object-write unproven HEAD changed the issued descriptor'
                    USING ERRCODE = '55000';
            END IF;

            IF unproven_source = 'authorized_precondition' THEN
                SELECT * INTO authorization_row
                  FROM __CATS_SCHEMA_IDENT__.control_object_write_gateway_qualification_lock_v1(
                    pg_catalog.convert_to(request_text, 'UTF8'),
                    1::BIGINT,
                    'object_write_ambiguity'::TEXT,
                    attempt_row.request_id,
                    attempt_row.writer_authority_id,
                    attempt_row.record #>> '{descriptor,credential,credential_id}',
                    attempt_row.record #>>
                        '{descriptor,credential,public_key_spki_sha256}',
                    attempt_row.provider_attempt_id,
                    'successful_put_response_loss'::TEXT,
                    attempt_row.record #>>
                        '{descriptor,qualification_fault,qualification_id}',
                    attempt_row.record #>> '{descriptor,qualification_fault,fault_id}',
                    attempt_row.record #>>
                        '{descriptor,qualification_fault,qualification_catalog_sha256}',
                    attempt_row.object_provider,
                    attempt_row.object_partition,
                    attempt_row.object_account_id,
                    attempt_row.object_region,
                    attempt_row.object_store_scope_id,
                    attempt_row.object_key,
                    attempt_row.content_sha256,
                    attempt_row.content_length
                  );
                IF authorization_row.request_canonical
                        IS DISTINCT FROM pg_catalog.convert_to(request_text, 'UTF8') THEN
                    RAISE EXCEPTION 'object-write unproven authorization changed its request'
                        USING ERRCODE = '55000';
                END IF;
            END IF;

            terminal_at := pg_catalog.floor(
                pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) * 1000
            )::BIGINT;
            IF terminal_at <
                    (requested_outcome #>> '{head_evidence,observed_at_unix_ms}')::BIGINT THEN
                RAISE EXCEPTION 'object-write unproven resolution time is invalid'
                    USING ERRCODE = '42501';
            END IF;
            IF unproven_source = 'authorized_precondition'
               AND terminal_at >= authorization_row.qualification_expires_at_unix_ms THEN
                RAISE EXCEPTION 'object-write unproven authorization expired before commit'
                    USING ERRCODE = '42501';
            END IF;
            hash_input :=
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    pg_catalog.convert_to(
                        'cats.object-write-qualification-unproven-visible.v1', 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(sealed_canonical) ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    pg_catalog.convert_to('response-loss-receipt-absent', 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(head_canonical) ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    pg_catalog.int8send(terminal_at));
            resolution_receipt_id := 'owqunp1_' ||
                pg_catalog.encode(pg_catalog.sha256(hash_input), 'hex');
            receipt_text := '{"version":1,"sealed_request":' || sealed_text ||
                ',"reason":"response_loss_receipt_absent","head_evidence":' || head_text ||
                ',"resolution_receipt_id":' ||
                pg_catalog.to_json(resolution_receipt_id)::TEXT ||
                ',"resolved_at_unix_ms":' || terminal_at::TEXT || '}';
            receipt_canonical := pg_catalog.convert_to(receipt_text, 'UTF8');
            outcome_text := '{"kind":"qualification_unproven_visible","receipt":' ||
                receipt_text || '}';
            requested_outcome := pg_catalog.convert_from(
                pg_catalog.convert_to(outcome_text, 'UTF8'), 'UTF8')::JSONB;
            expected_state := 'provider_issued';
        ELSE
            RAISE EXCEPTION 'object-write terminal outcome kind is invalid'
                USING ERRCODE = '22023';
        END IF;
    EXCEPTION
        WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            RAISE EXCEPTION 'object-write terminal time is invalid'
                USING ERRCODE = '22023';
    END;
    IF NOT unproven_intent AND pg_catalog.convert_to(outcome_text, 'UTF8')
            IS DISTINCT FROM requested_outcome_canonical THEN
        RAISE EXCEPTION 'object-write terminal outcome is not canonical'
            USING ERRCODE = '22023';
    END IF;
    IF terminal_at < attempt_row.provider_issued_at_unix_ms THEN
        RAISE EXCEPTION 'object-write terminal transition precedes provider issue'
            USING ERRCODE = '55000';
    END IF;
    IF unproven_intent THEN
        descriptor_text := '{"writer_authority_id":' ||
            pg_catalog.to_json(attempt_row.writer_authority_id)::TEXT ||
            ',"accepted_sequence":' || attempt_row.accepted_sequence::TEXT ||
            ',"request_id":' || pg_catalog.to_json(attempt_row.request_id)::TEXT ||
            ',"credential":{"credential_id":' || pg_catalog.to_json(
                attempt_row.record #>> '{descriptor,credential,credential_id}')::TEXT ||
            ',"public_key_spki_sha256":' || pg_catalog.to_json(
                attempt_row.record #>>
                    '{descriptor,credential,public_key_spki_sha256}')::TEXT ||
            '},"volume_id":' || pg_catalog.to_json(attempt_row.volume_id)::TEXT ||
            ',"key":' || key_text ||
            ',"target":{"object_provider_scope":{"provider":' ||
            pg_catalog.to_json(attempt_row.object_provider)::TEXT ||
            ',"partition":' || pg_catalog.to_json(attempt_row.object_partition)::TEXT ||
            ',"account_id":' || pg_catalog.to_json(attempt_row.object_account_id)::TEXT ||
            ',"region":' || pg_catalog.to_json(attempt_row.object_region)::TEXT ||
            '},"object_store_scope_id":' ||
            pg_catalog.to_json(attempt_row.object_store_scope_id)::TEXT ||
            ',"canonical_logical_key":' || pg_catalog.to_json(attempt_row.object_key)::TEXT ||
            '},"content_sha256":' || pg_catalog.to_json(attempt_row.content_sha256)::TEXT ||
            ',"content_length":' || attempt_row.content_length::TEXT ||
            ',"qualification_fault":' || fault_text ||
            ',"provider_attempt_id":' || pg_catalog.to_json(attempt_row.provider_attempt_id)::TEXT ||
            ',"accepted_at_unix_ms":' || attempt_row.accepted_at_unix_ms::TEXT || '}';
        spool_text := '{"spool_id":' || pg_catalog.to_json(attempt_row.spool_id)::TEXT ||
            ',"request_id":' || pg_catalog.to_json(attempt_row.request_id)::TEXT ||
            ',"content_sha256":' || pg_catalog.to_json(attempt_row.content_sha256)::TEXT ||
            ',"content_length":' || attempt_row.content_length::TEXT ||
            ',"file_fsync_receipt_id":' ||
            pg_catalog.to_json(attempt_row.spool_file_fsync_receipt_id)::TEXT ||
            ',"directory_fsync_receipt_id":' ||
            pg_catalog.to_json(attempt_row.spool_directory_fsync_receipt_id)::TEXT ||
            ',"durable_at_unix_ms":' || attempt_row.spool_durable_at_unix_ms::TEXT || '}';
        state_text := '{"kind":"terminal","outcome":' || outcome_text ||
            ',"spool":{"kind":"retained","spool":' || spool_text || '}}';
        attempt_text := '{"descriptor":' || descriptor_text || ',"state":' || state_text || '}';
        updated_record := pg_catalog.convert_from(
            pg_catalog.convert_to(attempt_text, 'UTF8'), 'UTF8')::JSONB;
    ELSE
        updated_record := pg_catalog.jsonb_set(
            attempt_row.record, '{state}',
            pg_catalog.jsonb_build_object(
                'kind', 'terminal',
                'outcome', requested_outcome,
                'spool', pg_catalog.jsonb_build_object(
                    'kind', 'retained',
                    'spool', attempt_row.record #> '{state,spool}'
                )
            ), FALSE
        );
    END IF;
    IF terminal_kind = 'succeeded_visible' THEN
        UPDATE __CATS_SCHEMA_IDENT__.object_write_attempts attempt
           SET record=updated_record, state='terminal_visible',
               terminal_kind='succeeded_visible',
               put_receipt_id=requested_outcome #>> '{put_receipt_id}',
               put_completed_at_unix_ms=
                    (requested_outcome #>> '{put_completed_at_unix_ms}')::BIGINT,
               visibility_receipt_id=requested_outcome #>> '{visibility_receipt_id}',
               visible_at_unix_ms=terminal_at,
               qualification_visibility_head_canonical=CASE
                   WHEN qualified_success THEN head_canonical ELSE NULL::BYTEA END
         WHERE attempt.request_id=requested_request_id
           AND attempt.state=expected_state;
    ELSIF terminal_kind = 'permanently_failed' THEN
        UPDATE __CATS_SCHEMA_IDENT__.object_write_attempts attempt
           SET record=updated_record, state='permanent',
               terminal_kind='permanently_failed',
               failure_receipt_id=requested_outcome #>> '{failure_receipt_id}',
               failed_at_unix_ms=terminal_at
         WHERE attempt.request_id=requested_request_id
           AND attempt.state=expected_state;
    ELSE
        UPDATE __CATS_SCHEMA_IDENT__.object_write_attempts attempt
           SET record=updated_record, state='qualification_unproven_visible',
               terminal_kind='qualification_unproven_visible',
               qualification_request_canonical=pg_catalog.convert_to(request_text, 'UTF8'),
               qualification_unproven_intent_canonical=requested_outcome_canonical,
               qualification_unproven_sealed_request_canonical=sealed_canonical,
               qualification_unproven_receipt_canonical=receipt_canonical,
               qualification_unproven_attempt_canonical=
                    pg_catalog.convert_to(attempt_text, 'UTF8'),
               qualification_unproven_resolution_receipt_id=resolution_receipt_id,
               qualification_unproven_reason='response_loss_receipt_absent',
               qualification_head_evidence_canonical=head_canonical,
               qualification_unproven_at_unix_ms=terminal_at
         WHERE attempt.request_id=requested_request_id
           AND attempt.state=expected_state;
    END IF;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write attempt changed before terminal settlement'
            USING ERRCODE = '55000';
    END IF;

    prefix_sequence := authority_row.terminal_prefix_sequence;
    prefix_sha256 := authority_row.terminal_prefix_sha256;
    expected_sequence := prefix_sequence + 1;
    FOR prefix_row IN
        SELECT attempt.accepted_sequence, attempt.request_id,
               attempt.object_key, attempt.content_sha256,
               attempt.content_length, attempt.terminal_kind,
               attempt.put_receipt_id, attempt.put_completed_at_unix_ms,
               attempt.visibility_receipt_id, attempt.visible_at_unix_ms,
               attempt.failure_receipt_id, attempt.failed_at_unix_ms,
               attempt.qualification_authorization_canonical,
               attempt.qualification_response_loss_canonical,
               attempt.qualification_injection_receipt_id,
               attempt.qualification_visibility_head_canonical,
               attempt.qualification_unproven_reason,
               attempt.qualification_head_evidence_canonical,
               attempt.qualification_unproven_receipt_canonical,
               attempt.record
          FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
         WHERE attempt.writer_authority_id=parent_id
           AND attempt.accepted_sequence > prefix_sequence
           AND attempt.state IN (
               'terminal_visible','permanent','qualification_unproven_visible','spool_removed'
           )
         ORDER BY attempt.accepted_sequence
         LIMIT 256
    LOOP
        IF prefix_row.accepted_sequence <> expected_sequence THEN
            EXIT;
        END IF;
        hash_input :=
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.convert_to('cats.object-write-terminal-prefix.v1', 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.convert_to(prefix_sha256, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.int8send(prefix_row.accepted_sequence)) ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.convert_to(prefix_row.request_id, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.convert_to(prefix_row.object_key, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.convert_to(prefix_row.content_sha256, 'UTF8')) ||
            __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                pg_catalog.int8send(prefix_row.content_length));
        IF prefix_row.terminal_kind = 'succeeded_visible' THEN
            hash_input := hash_input ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    pg_catalog.convert_to('succeeded-visible', 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    pg_catalog.convert_to(prefix_row.put_receipt_id, 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    pg_catalog.int8send(prefix_row.put_completed_at_unix_ms)) ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    pg_catalog.convert_to(prefix_row.visibility_receipt_id, 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    pg_catalog.int8send(prefix_row.visible_at_unix_ms));
            IF prefix_row.record #> '{state,outcome,qualification_ambiguity}'
                    IS DISTINCT FROM 'null'::JSONB THEN
                authorization_sha256 := 'sha256:' || pg_catalog.encode(
                    pg_catalog.sha256(
                        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                            pg_catalog.convert_to(
                                'cats.object-write-qualification-authorization.v1', 'UTF8')) ||
                        __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                            prefix_row.qualification_authorization_canonical)
                    ), 'hex');
                ambiguity_canonical := pg_catalog.convert_to(
                    '{"version":1,"response_loss":' || pg_catalog.convert_from(
                        prefix_row.qualification_response_loss_canonical, 'UTF8') ||
                    ',"head":' || pg_catalog.convert_from(
                        prefix_row.qualification_visibility_head_canonical, 'UTF8') || '}',
                    'UTF8');
                ambiguity_sha256 := 'sha256:' || pg_catalog.encode(
                    pg_catalog.sha256(ambiguity_canonical), 'hex');
                hash_input := hash_input ||
                    __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                        pg_catalog.convert_to('qualification-ambiguity', 'UTF8')) ||
                    __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                        pg_catalog.convert_to(authorization_sha256, 'UTF8')) ||
                    __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                        pg_catalog.convert_to(
                            prefix_row.qualification_injection_receipt_id, 'UTF8')) ||
                    __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                        pg_catalog.convert_to(ambiguity_sha256, 'UTF8'));
            END IF;
        ELSIF prefix_row.terminal_kind = 'permanently_failed' THEN
            hash_input := hash_input ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    pg_catalog.convert_to('permanently-failed', 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    pg_catalog.convert_to(prefix_row.failure_receipt_id, 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    pg_catalog.int8send(prefix_row.failed_at_unix_ms));
        ELSIF prefix_row.terminal_kind = 'qualification_unproven_visible' THEN
            hash_input := hash_input ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    pg_catalog.convert_to('qualification-unproven-visible', 'UTF8')) ||
                __CATS_SCHEMA_IDENT__.control_object_write_gateway_frame_v1(
                    prefix_row.qualification_unproven_receipt_canonical);
        ELSE
            RAISE EXCEPTION 'object-write terminal projection is invalid'
                USING ERRCODE = '55000';
        END IF;
        prefix_sha256 := 'sha256:' ||
            pg_catalog.encode(pg_catalog.sha256(hash_input), 'hex');
        prefix_sequence := prefix_row.accepted_sequence;
        expected_sequence := prefix_sequence + 1;
    END LOOP;
    updated_authority := pg_catalog.jsonb_set(
        pg_catalog.jsonb_set(
            authority_row.record,
            '{terminal_prefix_sequence}', pg_catalog.to_jsonb(prefix_sequence), FALSE
        ),
        '{terminal_prefix_sha256}', pg_catalog.to_jsonb(prefix_sha256), FALSE
    );
    UPDATE __CATS_SCHEMA_IDENT__.object_write_authorities authority
       SET record=updated_authority,
           terminal_prefix_sequence=prefix_sequence,
           terminal_prefix_sha256=prefix_sha256
     WHERE authority.writer_authority_id=parent_id;
    RETURN QUERY SELECT updated_record::TEXT, updated_authority::TEXT;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_terminal_v1(TEXT,BYTEA) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_spool_removed_v1(
    requested_request_id TEXT,
    requested_removal_receipt_id TEXT
)
RETURNS TABLE(record_json TEXT, authority_json TEXT)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    parent_id TEXT;
    authority_row RECORD;
    attempt_row RECORD;
    now_ms BIGINT;
    terminal_at BIGINT;
    updated_record JSONB;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway' THEN
        RAISE EXCEPTION 'object-write gateway PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF requested_removal_receipt_id IS NULL
       OR pg_catalog.octet_length(requested_removal_receipt_id) NOT BETWEEN 1 AND 512
       OR requested_removal_receipt_id !~ '^[ -~]+$' THEN
        RAISE EXCEPTION 'object-write spool removal receipt is invalid'
            USING ERRCODE = '22023';
    END IF;
    SELECT attempt.writer_authority_id INTO parent_id
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.request_id=requested_request_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write attempt does not exist'
            USING ERRCODE = 'P0002';
    END IF;
    SELECT authority.* INTO authority_row
      FROM __CATS_SCHEMA_IDENT__.object_write_authorities authority
     WHERE authority.writer_authority_id=parent_id
     FOR UPDATE;
    SELECT attempt.* INTO attempt_row
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.request_id=requested_request_id
     FOR UPDATE;
    IF authority_row.writer_authority_id IS NULL
       OR attempt_row.accepted_sequence IS NULL THEN
        RAISE EXCEPTION 'object-write request has not been accepted'
            USING ERRCODE = '55000';
    END IF;
    IF attempt_row.state = 'spool_removed' THEN
        RETURN QUERY SELECT attempt_row.record::TEXT, authority_row.record::TEXT;
        RETURN;
    END IF;
    IF attempt_row.state NOT IN (
        'terminal_visible','permanent','qualification_unproven_visible'
    ) THEN
        RAISE EXCEPTION 'object-write request is not terminal'
            USING ERRCODE = '55000';
    END IF;
    terminal_at := COALESCE(
        attempt_row.visible_at_unix_ms,
        attempt_row.failed_at_unix_ms,
        attempt_row.qualification_unproven_at_unix_ms
    );
    now_ms := pg_catalog.floor(
        pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) * 1000
    )::BIGINT;
    IF now_ms < terminal_at THEN
        RAISE EXCEPTION 'object-write spool removal precedes terminal result'
            USING ERRCODE = '55000';
    END IF;
    updated_record := pg_catalog.jsonb_set(
        attempt_row.record, '{state,spool}',
        pg_catalog.jsonb_build_object(
            'kind', 'removed',
            'spool', attempt_row.record #> '{state,spool,spool}',
            'removal_receipt_id', requested_removal_receipt_id,
            'removed_at_unix_ms', now_ms
        ), FALSE
    );
    UPDATE __CATS_SCHEMA_IDENT__.object_write_attempts attempt
       SET record=updated_record, state='spool_removed',
           spool_removal_receipt_id=requested_removal_receipt_id,
           spool_removed_at_unix_ms=now_ms
     WHERE attempt.request_id=requested_request_id
       AND attempt.state IN (
           'terminal_visible','permanent','qualification_unproven_visible'
       );
    IF NOT FOUND THEN
        RAISE EXCEPTION 'object-write terminal row changed before spool removal'
            USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT updated_record::TEXT, authority_row.record::TEXT;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_spool_removed_v1(
        TEXT,TEXT) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_recover_ingress_v1(
    requested_after_request_id TEXT
)
RETURNS TABLE(request_id TEXT, state TEXT, record_json TEXT)
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway' THEN
        RAISE EXCEPTION 'object-write gateway PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF requested_after_request_id IS NOT NULL
       AND requested_after_request_id !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'object-write recovery cursor is invalid'
            USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT attempt.request_id, attempt.state, attempt.record::TEXT
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
     WHERE attempt.state IN (
        'receiving','durable_spooled','rejected_before_accept'
     )
       AND (requested_after_request_id IS NULL
            OR attempt.request_id COLLATE "C" > requested_after_request_id COLLATE "C")
     ORDER BY attempt.request_id COLLATE "C"
     LIMIT 256;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_recover_ingress_v1(TEXT) FROM PUBLIC;

CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_recover_accepted_v1(
    requested_after_request_id TEXT
)
RETURNS TABLE(
    request_id TEXT,
    state TEXT,
    record_json TEXT,
    authority_json TEXT
)
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway' THEN
        RAISE EXCEPTION 'object-write gateway PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF requested_after_request_id IS NOT NULL
       AND requested_after_request_id !~ '^sha256:[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'object-write recovery cursor is invalid'
            USING ERRCODE = '22023';
    END IF;
    RETURN QUERY
    SELECT attempt.request_id, attempt.state, attempt.record::TEXT,
           authority.record::TEXT
      FROM __CATS_SCHEMA_IDENT__.object_write_attempts attempt
      JOIN __CATS_SCHEMA_IDENT__.object_write_authorities authority
        ON authority.writer_authority_id=attempt.writer_authority_id
     WHERE attempt.state IN (
        'accepted_spooled','provider_issued','qualification_response_lost',
        'terminal_visible','permanent','qualification_unproven_visible'
     )
       AND (requested_after_request_id IS NULL
            OR attempt.request_id COLLATE "C" > requested_after_request_id COLLATE "C")
     ORDER BY attempt.request_id COLLATE "C"
     LIMIT 256;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_recover_accepted_v1(TEXT) FROM PUBLIC;

-- ADR-0055 §4: the E13 fault path opens one exclusive guard serialized by the
-- exact request, and reads the current Qualification admission while holding a
-- FOR SHARE lock on its singleton. Both locks stay held by the caller's
-- transaction across the real provider PUT and the durable response-loss
-- receipt, so a successful End or EmergencyClose can never return before this
-- effect is either committed or rolled back. Every authorized fact is derived
-- here from the current admission; the caller submits none of them.
CREATE OR REPLACE FUNCTION __CATS_SCHEMA_IDENT__.control_object_write_gateway_qualification_lock_v1(
    p_request_canonical BYTEA,
    p_version BIGINT,
    p_mutation_class TEXT,
    p_request_id TEXT,
    p_writer_authority_id TEXT,
    p_credential_id TEXT,
    p_credential_public_key_spki_sha256 TEXT,
    p_provider_attempt_id TEXT,
    p_fault_kind TEXT,
    p_qualification_id TEXT,
    p_fault_id TEXT,
    p_fault_catalog_sha256 TEXT,
    p_provider TEXT,
    p_partition TEXT,
    p_account_id TEXT,
    p_region TEXT,
    p_object_store_scope_id TEXT,
    p_canonical_logical_key TEXT,
    p_content_sha256 TEXT,
    p_content_length BIGINT
)
RETURNS TABLE(
    request_canonical BYTEA,
    authorization_canonical BYTEA,
    authorization_version BIGINT,
    authorization_mutation_class TEXT,
    qualification_id TEXT,
    workspace_id TEXT,
    deployment_id TEXT,
    release_id TEXT,
    source_commit_sha TEXT,
    control_schema_version BIGINT,
    qualification_catalog_sha256 TEXT,
    admission_binding_sha256 TEXT,
    admission_revision BIGINT,
    authorized_at_unix_ms BIGINT,
    qualification_expires_at_unix_ms BIGINT
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    admission_row RECORD;
    request_json JSONB;
    request_text TEXT;
    fault_text TEXT;
    authorization_text TEXT;
    authorization_bytes BYTEA;
    now_ms BIGINT;
BEGIN
    IF session_user::TEXT IS DISTINCT FROM 'cats_object_write_gateway' THEN
        RAISE EXCEPTION 'object-write gateway PostgreSQL role mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF p_version IS DISTINCT FROM 1
       OR p_mutation_class IS DISTINCT FROM 'object_write_ambiguity'
       OR p_fault_kind IS DISTINCT FROM 'successful_put_response_loss' THEN
        RAISE EXCEPTION 'object-write qualification lock class is not E13'
            USING ERRCODE = '22023';
    END IF;

    -- The caller may not assert its own request: rebuild the canonical request
    -- from the exact arguments and require it to be the bytes it presented.
    fault_text := '{"kind":"successful_put_response_loss","qualification_id":' ||
        pg_catalog.to_json(p_qualification_id)::TEXT ||
        ',"fault_id":' || pg_catalog.to_json(p_fault_id)::TEXT ||
        ',"qualification_catalog_sha256":' ||
        pg_catalog.to_json(p_fault_catalog_sha256)::TEXT || '}';
    request_text := '{"version":1,"mutation_class":"object_write_ambiguity","request_id":' ||
        pg_catalog.to_json(p_request_id)::TEXT ||
        ',"writer_authority_id":' || pg_catalog.to_json(p_writer_authority_id)::TEXT ||
        ',"credential":{"credential_id":' || pg_catalog.to_json(p_credential_id)::TEXT ||
        ',"public_key_spki_sha256":' ||
        pg_catalog.to_json(p_credential_public_key_spki_sha256)::TEXT ||
        '},"provider_attempt_id":' || pg_catalog.to_json(p_provider_attempt_id)::TEXT ||
        ',"fault":' || fault_text ||
        ',"object_provider_scope":{"provider":' || pg_catalog.to_json(p_provider)::TEXT ||
        ',"partition":' || pg_catalog.to_json(p_partition)::TEXT ||
        ',"account_id":' || pg_catalog.to_json(p_account_id)::TEXT ||
        ',"region":' || pg_catalog.to_json(p_region)::TEXT ||
        '},"object_store_scope_id":' || pg_catalog.to_json(p_object_store_scope_id)::TEXT ||
        ',"canonical_logical_key":' || pg_catalog.to_json(p_canonical_logical_key)::TEXT ||
        ',"content_sha256":' || pg_catalog.to_json(p_content_sha256)::TEXT ||
        ',"content_length":' || p_content_length::TEXT || '}';
    IF pg_catalog.convert_to(request_text, 'UTF8') IS DISTINCT FROM p_request_canonical THEN
        RAISE EXCEPTION 'object-write qualification lock request is not canonical'
            USING ERRCODE = '22023';
    END IF;
    request_json := pg_catalog.convert_from(p_request_canonical, 'UTF8')::JSONB;
    IF request_json IS NULL THEN
        RAISE EXCEPTION 'object-write qualification lock request is not an object'
            USING ERRCODE = '22023';
    END IF;

    -- Exclusive guard serialized by the exact request. It is a transaction lock,
    -- so it is released only by commit or rollback -- never between the provider
    -- PUT and the resolution write.
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'cats.object-write.qualification-request.v1' || pg_catalog.encode(
                pg_catalog.sha256(p_request_canonical), 'hex'),
            0));

    -- The E13 lock. FOR SHARE blocks End/EmergencyClose (which take FOR UPDATE)
    -- until this transaction settles, and is itself blocked while one is running.
    SELECT admission.* INTO admission_row
      FROM __CATS_SCHEMA_IDENT__.production_mutation_admission admission
     WHERE admission.singleton
       FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'production mutation admission is absent'
            USING ERRCODE = 'P0002';
    END IF;
    now_ms := (EXTRACT(EPOCH FROM pg_catalog.clock_timestamp()) * 1000)::BIGINT;
    IF admission_row.mode IS DISTINCT FROM 'qualification'
       OR admission_row.binding_kind IS DISTINCT FROM 'qualification'
       OR admission_row.qualification_id IS NULL
       OR admission_row.qualification_id IS DISTINCT FROM p_qualification_id
       OR admission_row.qualification_catalog_sha256 IS DISTINCT FROM p_fault_catalog_sha256
       OR admission_row.qualification_workspace_id IS NULL
       OR admission_row.deployment_id IS NULL
       OR admission_row.release_id IS NULL
       OR admission_row.source_commit_sha IS NULL
       OR admission_row.control_schema_version IS DISTINCT FROM 18
       OR admission_row.binding_sha256 IS NULL
       OR admission_row.qualification_expires_at_unix_ms IS NULL
       OR admission_row.qualification_expires_at_unix_ms <= now_ms
       OR NOT (admission_row.binding #> '{allowed_mutation_classes}'
               @> '["object_write_ambiguity"]'::JSONB) THEN
        RAISE EXCEPTION 'current Qualification does not admit this object write'
            USING ERRCODE = '55000';
    END IF;

    authorization_text := '{"version":1,"mutation_class":"object_write_ambiguity"' ||
        ',"qualification_id":' || pg_catalog.to_json(admission_row.qualification_id)::TEXT ||
        ',"workspace_id":' ||
        pg_catalog.to_json(admission_row.qualification_workspace_id)::TEXT ||
        ',"deployment_id":' || pg_catalog.to_json(admission_row.deployment_id)::TEXT ||
        ',"release_id":' || pg_catalog.to_json(admission_row.release_id)::TEXT ||
        ',"source_commit_sha":' || pg_catalog.to_json(admission_row.source_commit_sha)::TEXT ||
        ',"control_schema_version":' || admission_row.control_schema_version::TEXT ||
        ',"qualification_catalog_sha256":' ||
        pg_catalog.to_json(admission_row.qualification_catalog_sha256)::TEXT ||
        ',"admission_binding_sha256":' ||
        pg_catalog.to_json(admission_row.binding_sha256)::TEXT ||
        ',"admission_revision":' || admission_row.revision::TEXT ||
        ',"request":' || request_text ||
        ',"authorized_at_unix_ms":' || now_ms::TEXT ||
        ',"qualification_expires_at_unix_ms":' ||
        admission_row.qualification_expires_at_unix_ms::TEXT || '}';
    authorization_bytes := pg_catalog.convert_to(authorization_text, 'UTF8');
    IF pg_catalog.convert_from(authorization_bytes, 'UTF8')::JSONB IS NULL THEN
        RAISE EXCEPTION 'object-write qualification authorization is not canonical'
            USING ERRCODE = '55000';
    END IF;

    RETURN QUERY SELECT
        p_request_canonical,
        authorization_bytes,
        1::BIGINT,
        'object_write_ambiguity'::TEXT,
        admission_row.qualification_id::TEXT,
        admission_row.qualification_workspace_id::TEXT,
        admission_row.deployment_id::TEXT,
        admission_row.release_id::TEXT,
        admission_row.source_commit_sha::TEXT,
        admission_row.control_schema_version::BIGINT,
        admission_row.qualification_catalog_sha256::TEXT,
        admission_row.binding_sha256::TEXT,
        admission_row.revision::BIGINT,
        now_ms,
        admission_row.qualification_expires_at_unix_ms::BIGINT;
END;
$function$;
REVOKE ALL ON FUNCTION
    __CATS_SCHEMA_IDENT__.control_object_write_gateway_qualification_lock_v1(
        BYTEA,BIGINT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,
        TEXT,TEXT,TEXT,BIGINT) FROM PUBLIC;
