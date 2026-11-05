<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/*
| docs/database-design.md §3.12, §4.2, §4.5.
|
| The application role stops inserting into audit_logs directly: appends go through the
| SECURITY DEFINER function audit_append(), the only code that chooses chain_seq and the hashes.
|
| Chain columns cannot be rebuilt for existing rows, so both directions refuse to run while
| audit_logs has rows. The id sequence is deliberately left alone.
*/
return new class extends Migration
{
    private const NIL = '00000000-0000-0000-0000-000000000000';

    public function up(): void
    {
        $this->refuseIfAuditRowsExist();

        // Null under --pretend, where nothing runs.
        if ((DB::selectOne('SELECT getdatabaseencoding() AS encoding')->encoding ?? 'UTF8') !== 'UTF8') {
            throw new RuntimeException('The audit hash is defined over UTF-8: the database encoding must be UTF8.');
        }

        $this->alterTables();
        $this->createHeads();
        $this->createFunctions();
        $this->grant();
    }

    public function down(): void
    {
        $this->refuseIfAuditRowsExist();

        DB::statement('DROP FUNCTION public.audit_append(uuid, uuid, text, uuid, text, text, uuid, text, text, inet, uuid, jsonb)');
        DB::statement('DROP FUNCTION public.audit_canonical(uuid, bigint, text, uuid, uuid, text, uuid, text, text, uuid, text, text, inet, uuid, jsonb, timestamptz)');
        DB::statement('DROP FUNCTION public.audit_field(text)');
        DB::statement('DROP FUNCTION public.audit_metadata_is_valid(jsonb)');
        DB::statement('DROP TABLE audit_chain_heads');
        DB::statement('DROP FUNCTION public.audit_chain_heads_guard()');

        DB::statement(<<<'SQL'
            ALTER TABLE audit_logs
              DROP CONSTRAINT audit_logs_chain_position_key,
              DROP CONSTRAINT audit_logs_organization_not_nil,
              DROP CONSTRAINT audit_logs_actor_consistent,
              DROP CONSTRAINT audit_logs_severity_check,
              DROP CONSTRAINT audit_logs_ip_is_host,
              DROP CONSTRAINT audit_logs_metadata_is_object,
              DROP CONSTRAINT audit_logs_prev_hash_format,
              DROP CONSTRAINT audit_logs_hash_format,
              DROP COLUMN chain_id,
              DROP COLUMN chain_seq,
              DROP COLUMN hash_version
            SQL);
        DB::statement('ALTER TABLE organizations DROP CONSTRAINT organizations_id_not_nil');
        DB::statement('ALTER TABLE users DROP COLUMN password_change_key_hash, DROP COLUMN password_change_previous_hash');

        $app = $this->appRole();
        DB::statement(<<<SQL
            GRANT INSERT (
              event_id, organization_id, actor_type, actor_user_id, event_type, resource_type,
              resource_id, result, severity, ip_address, request_id, metadata, occurred_at,
              prev_hash, hash
            ) ON audit_logs TO {$app}
            SQL);
    }

    private function refuseIfAuditRowsExist(): void
    {
        if (DB::selectOne('SELECT EXISTS (SELECT 1 FROM audit_logs) AS has_rows')->has_rows ?? false) {
            throw new RuntimeException('audit_logs has rows: the chain columns cannot be rebuilt or dropped safely.');
        }
    }

    private function appRole(): string
    {
        return '"'.str_replace('"', '""', config()->string('database.connections.pgsql.username')).'"';
    }

    private function alterTables(): void
    {
        $nil = self::NIL;

        DB::statement("ALTER TABLE organizations ADD CONSTRAINT organizations_id_not_nil CHECK (id <> '{$nil}')");

        DB::statement(<<<'SQL'
            ALTER TABLE users
              ADD COLUMN password_change_key_hash char(64) NULL
                CONSTRAINT users_password_change_key_hash_format CHECK (password_change_key_hash ~ '^[0-9a-f]{64}$'),
              ADD COLUMN password_change_previous_hash varchar(255) NULL
            SQL);

        DB::statement(<<<SQL
            ALTER TABLE audit_logs
              ADD COLUMN chain_id uuid NOT NULL GENERATED ALWAYS AS (COALESCE(organization_id, '{$nil}'::uuid)) STORED,
              ADD COLUMN chain_seq bigint NOT NULL CONSTRAINT audit_logs_chain_seq_positive CHECK (chain_seq >= 1),
              ADD COLUMN hash_version smallint NOT NULL CONSTRAINT audit_logs_hash_version_known CHECK (hash_version = 1),
              ADD CONSTRAINT audit_logs_chain_position_key UNIQUE (chain_id, chain_seq),
              ADD CONSTRAINT audit_logs_organization_not_nil CHECK (organization_id <> '{$nil}'),
              ADD CONSTRAINT audit_logs_actor_consistent CHECK ((actor_type = 'user') = (actor_user_id IS NOT NULL)),
              ADD CONSTRAINT audit_logs_severity_check CHECK (severity IN ('low', 'medium', 'high', 'critical')),
              ADD CONSTRAINT audit_logs_ip_is_host CHECK (
                ip_address IS NULL OR masklen(ip_address) = CASE family(ip_address) WHEN 4 THEN 32 ELSE 128 END
              ),
              ADD CONSTRAINT audit_logs_metadata_is_object CHECK (jsonb_typeof(metadata) = 'object'),
              ADD CONSTRAINT audit_logs_prev_hash_format CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
              ADD CONSTRAINT audit_logs_hash_format CHECK (hash ~ '^[0-9a-f]{64}$')
            SQL);
    }

    private function createHeads(): void
    {
        DB::statement(<<<'SQL'
            CREATE TABLE audit_chain_heads (
              chain_id uuid PRIMARY KEY,
              last_seq bigint NOT NULL CHECK (last_seq >= 0),
              last_hash char(64) NOT NULL CHECK (last_hash ~ '^[0-9a-f]{64}$'),
              updated_at timestamptz NOT NULL
            )
            SQL);

        // A guard against owner mistakes. It cannot stop an owner who disables the trigger (§5).
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION public.audit_chain_heads_guard() RETURNS trigger
            LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
            BEGIN
              IF TG_OP = 'UPDATE' AND NEW.chain_id = OLD.chain_id AND NEW.last_seq = OLD.last_seq + 1 THEN
                RETURN NEW;
              END IF;
              RAISE EXCEPTION 'audit_chain_heads only moves forward' USING ERRCODE = 'insufficient_privilege';
            END $f$
            SQL);
        DB::statement('CREATE TRIGGER audit_chain_heads_forward_only BEFORE UPDATE OR DELETE ON audit_chain_heads FOR EACH ROW EXECUTE FUNCTION public.audit_chain_heads_guard()');
        DB::statement('CREATE TRIGGER audit_chain_heads_no_truncate BEFORE TRUNCATE ON audit_chain_heads FOR EACH STATEMENT EXECUTE FUNCTION public.audit_chain_heads_guard()');
    }

    private function createFunctions(): void
    {
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION public.audit_field(v text) RETURNS text
            LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $f$
              SELECT CASE WHEN v IS NULL THEN '-' ELSE octet_length(convert_to(v, 'UTF8'))::text || ':' || v END
            $f$
            SQL);

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION public.audit_canonical(
              p_chain uuid, p_seq bigint, p_prev text, p_event uuid, p_org uuid, p_actor_type text, p_actor uuid,
              p_type text, p_res_type text, p_res uuid, p_result text, p_sev text, p_ip inet, p_req uuid,
              p_meta jsonb, p_at timestamptz
            ) RETURNS text
            LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
              SELECT 'secureflow.audit.v1|' || concat_ws('|',
                public.audit_field(p_chain::text), public.audit_field(p_seq::text), public.audit_field(p_prev),
                public.audit_field(p_event::text), public.audit_field(p_org::text), public.audit_field(p_actor_type),
                public.audit_field(p_actor::text), public.audit_field(p_type), public.audit_field(p_res_type),
                public.audit_field(p_res::text), public.audit_field(p_result), public.audit_field(p_sev),
                public.audit_field(host(p_ip)), public.audit_field(p_req::text), public.audit_field(p_meta::text),
                public.audit_field(to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')))
            $f$
            SQL);

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION public.audit_metadata_is_valid(p jsonb) RETURNS boolean
            LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $f$
            DECLARE k text; v jsonb; n integer := 0; t text;
            BEGIN
              IF jsonb_typeof(p) <> 'object' OR octet_length(convert_to(p::text, 'UTF8')) > 4096 THEN
                RETURN false;
              END IF;
              FOR k, v IN SELECT key, value FROM jsonb_each(p) LOOP
                n := n + 1;
                IF n > 16 OR k !~ '^[a-z][a-z0-9_]{0,63}$' THEN RETURN false; END IF;
                t := jsonb_typeof(v);
                IF t = 'string' THEN
                  IF octet_length(convert_to(v #>> '{}', 'UTF8')) > 1024 OR (v #>> '{}') ~ '[\x01-\x1f\x7f]' THEN RETURN false; END IF;
                ELSIF t = 'number' THEN
                  IF v::text !~ '^-?[0-9]+$' OR abs((v #>> '{}')::numeric) > 9007199254740991 THEN RETURN false; END IF;
                ELSIF t <> 'boolean' THEN
                  RETURN false;
                END IF;
              END LOOP;
              RETURN true;
            END $f$
            SQL);

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION public.audit_append(
              p_event_id uuid, p_organization_id uuid, p_actor_type text, p_actor_user_id uuid,
              p_event_type text, p_resource_type text, p_resource_id uuid, p_result text,
              p_severity text, p_ip_address inet, p_request_id uuid, p_metadata jsonb
            ) RETURNS bigint
            LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET lock_timeout = '2s' AS $f$
            DECLARE
              c_nil constant uuid := '00000000-0000-0000-0000-000000000000';
              v_chain uuid := COALESCE(p_organization_id, c_nil);
              v_seq bigint; v_prev text; v_at timestamptz; v_hash text; v_constraint text;
              r public.audit_logs;
            BEGIN
              IF p_event_id IS NULL OR p_actor_type IS NULL OR p_event_type IS NULL OR p_result IS NULL OR p_metadata IS NULL THEN
                RAISE EXCEPTION 'audit_append: a required argument is missing' USING ERRCODE = '22023';
              END IF;
              IF length(p_event_type) > 64 OR p_event_type !~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$' THEN
                RAISE EXCEPTION 'audit_append: invalid event type' USING ERRCODE = '22023';
              END IF;
              IF p_organization_id = c_nil THEN
                RAISE EXCEPTION 'audit_append: invalid organization' USING ERRCODE = '22023';
              END IF;
              IF p_organization_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.organizations WHERE id = p_organization_id) THEN
                RAISE EXCEPTION 'audit_append: unknown organization' USING ERRCODE = '22023';
              END IF;
              IF p_actor_type = 'user' THEN
                IF p_actor_user_id IS NULL OR p_organization_id IS NULL OR NOT EXISTS (
                  SELECT 1 FROM public.users WHERE id = p_actor_user_id AND organization_id = p_organization_id
                ) THEN
                  RAISE EXCEPTION 'audit_append: actor does not belong to the organization' USING ERRCODE = '22023';
                END IF;
              ELSIF p_actor_type NOT IN ('system', 'anonymous') OR p_actor_user_id IS NOT NULL THEN
                RAISE EXCEPTION 'audit_append: invalid actor' USING ERRCODE = '22023';
              END IF;
              IF p_resource_type IS NOT NULL AND p_resource_type !~ '^[a-z][a-z0-9_]{0,31}$' THEN
                RAISE EXCEPTION 'audit_append: invalid resource type' USING ERRCODE = '22023';
              END IF;
              IF p_resource_id IS NOT NULL AND p_resource_type IS NULL THEN
                RAISE EXCEPTION 'audit_append: resource id without a type' USING ERRCODE = '22023';
              END IF;
              IF p_result NOT IN ('success', 'failure', 'denied') THEN
                RAISE EXCEPTION 'audit_append: invalid result' USING ERRCODE = '22023';
              END IF;
              IF p_severity IS NOT NULL AND p_severity NOT IN ('low', 'medium', 'high', 'critical') THEN
                RAISE EXCEPTION 'audit_append: invalid severity' USING ERRCODE = '22023';
              END IF;
              IF p_ip_address IS NOT NULL AND masklen(p_ip_address) <> (CASE family(p_ip_address) WHEN 4 THEN 32 ELSE 128 END) THEN
                RAISE EXCEPTION 'audit_append: the address must be a host' USING ERRCODE = '22023';
              END IF;
              IF NOT public.audit_metadata_is_valid(p_metadata) THEN
                RAISE EXCEPTION 'audit_append: invalid metadata' USING ERRCODE = '22023';
              END IF;

              INSERT INTO public.audit_chain_heads (chain_id, last_seq, last_hash, updated_at)
                VALUES (v_chain, 0, repeat('0', 64), clock_timestamp())
                ON CONFLICT (chain_id) DO NOTHING;
              SELECT last_seq + 1, last_hash INTO STRICT v_seq, v_prev
                FROM public.audit_chain_heads WHERE chain_id = v_chain FOR UPDATE;

              v_at := clock_timestamp();
              v_hash := encode(sha256(convert_to(public.audit_canonical(
                v_chain, v_seq, v_prev, p_event_id, p_organization_id, p_actor_type, p_actor_user_id, p_event_type,
                p_resource_type, p_resource_id, p_result, p_severity, p_ip_address, p_request_id, p_metadata, v_at
              ), 'UTF8')), 'hex');

              -- Only this event type enters the exception block: it costs a subtransaction, and
              -- ordinary appends must keep their plain unique_violation.
              IF p_event_type = 'audit.availability_checked' THEN
                BEGIN
                  INSERT INTO public.audit_logs (event_id, organization_id, chain_seq, hash_version, actor_type, actor_user_id, event_type, resource_type, resource_id, result, severity, ip_address, request_id, metadata, occurred_at, prev_hash, hash)
                  VALUES (p_event_id, p_organization_id, v_seq, 1, p_actor_type, p_actor_user_id, p_event_type, p_resource_type, p_resource_id, p_result, p_severity, p_ip_address, p_request_id, p_metadata, v_at, v_prev, v_hash);
                EXCEPTION WHEN unique_violation THEN
                  GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
                  IF v_constraint = 'audit_logs_event_id_key' THEN
                    SELECT * INTO r FROM public.audit_logs WHERE event_id = p_event_id;
                    IF FOUND AND r.event_type = p_event_type AND r.chain_id = v_chain
                       AND (p_metadata ->> 'outage_id') IS NOT NULL
                       AND r.metadata ->> 'outage_id' = p_metadata ->> 'outage_id' THEN
                      RAISE EXCEPTION 'audit_append: already recorded' USING ERRCODE = 'SF001';
                    END IF;
                  END IF;
                  RAISE;
                END;
              ELSE
                INSERT INTO public.audit_logs (event_id, organization_id, chain_seq, hash_version, actor_type, actor_user_id, event_type, resource_type, resource_id, result, severity, ip_address, request_id, metadata, occurred_at, prev_hash, hash)
                VALUES (p_event_id, p_organization_id, v_seq, 1, p_actor_type, p_actor_user_id, p_event_type, p_resource_type, p_resource_id, p_result, p_severity, p_ip_address, p_request_id, p_metadata, v_at, v_prev, v_hash);
              END IF;

              UPDATE public.audit_chain_heads SET last_seq = v_seq, last_hash = v_hash, updated_at = v_at WHERE chain_id = v_chain;
              RETURN v_seq;
            END $f$
            SQL);
    }

    private function grant(): void
    {
        $app = $this->appRole();

        DB::statement("REVOKE INSERT ON audit_logs FROM {$app}");
        DB::statement("GRANT SELECT ON audit_chain_heads TO {$app}");

        foreach ([
            'public.audit_append(uuid, uuid, text, uuid, text, text, uuid, text, text, inet, uuid, jsonb)',
            'public.audit_canonical(uuid, bigint, text, uuid, uuid, text, uuid, text, text, uuid, text, text, inet, uuid, jsonb, timestamptz)',
            'public.audit_field(text)',
            'public.audit_metadata_is_valid(jsonb)',
            'public.audit_chain_heads_guard()',
        ] as $function) {
            DB::statement("REVOKE ALL ON FUNCTION {$function} FROM PUBLIC");
        }

        DB::statement("GRANT EXECUTE ON FUNCTION public.audit_append(uuid, uuid, text, uuid, text, text, uuid, text, text, inet, uuid, jsonb) TO {$app}");
    }
};
