<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/*
| docs/database-design.md §3.12, §4.2, §5.
|
| Append-only. The application role gets SELECT and a column-level INSERT that leaves out id,
| and no privilege on the IDENTITY sequence, so it cannot choose or burn ids.
|
| id is a row identifier, not the chain order: it does not follow commit order. Chain columns,
| their constraints and privileges are designed together in step 1-3. A column added later needs
| its own INSERT grant; a missing grant fails closed.
*/
return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            CREATE TABLE audit_logs (
              id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
              event_id uuid NOT NULL UNIQUE,
              organization_id uuid NULL,
              actor_type varchar(16) NOT NULL CHECK (actor_type IN ('user', 'system', 'anonymous')),
              actor_user_id uuid NULL,
              event_type varchar(64) NOT NULL,
              resource_type varchar(32) NULL,
              resource_id uuid NULL,
              result varchar(8) NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
              severity varchar(8) NULL,
              ip_address inet NULL,
              request_id uuid NULL,
              metadata jsonb NOT NULL DEFAULT '{}',
              occurred_at timestamptz NOT NULL,
              prev_hash char(64) NOT NULL,
              hash char(64) NOT NULL
            )
            SQL);

        DB::statement('CREATE INDEX audit_logs_organization_occurred_index ON audit_logs (organization_id, occurred_at DESC)');
        DB::statement('CREATE INDEX audit_logs_organization_event_occurred_index ON audit_logs (organization_id, event_type, occurred_at DESC)');
        DB::statement('CREATE INDEX audit_logs_actor_occurred_index ON audit_logs (actor_user_id, occurred_at DESC)');

        DB::statement('CREATE TRIGGER audit_logs_no_update BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION forbid_mutation()');
        DB::statement('CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation()');

        $app = '"'.str_replace('"', '""', config()->string('database.connections.pgsql.username')).'"';
        DB::statement("GRANT SELECT ON audit_logs TO {$app}");
        DB::statement(<<<SQL
            GRANT INSERT (
              event_id, organization_id, actor_type, actor_user_id, event_type, resource_type,
              resource_id, result, severity, ip_address, request_id, metadata, occurred_at,
              prev_hash, hash
            ) ON audit_logs TO {$app}
            SQL);
    }

    public function down(): void
    {
        DB::statement('DROP TABLE audit_logs');
    }
};
