<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/*
| docs/database-design.md §3.14 (step 3-3). A run is updated as it goes; its results are never changed. One run
| at a time per organization, by a partial unique index that the application also checks under the organization's lock.
*/
return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            CREATE TABLE security_test_runs (
              id uuid PRIMARY KEY,
              organization_id uuid NOT NULL REFERENCES organizations (id),
              triggered_by uuid NULL,
              status varchar(16) NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
              total integer NOT NULL DEFAULT 0 CHECK (total >= 0),
              passed integer NOT NULL DEFAULT 0 CHECK (passed >= 0),
              failed integer NOT NULL DEFAULT 0 CHECK (failed >= 0),
              ruleset_version varchar(64) NULL,
              policy_version varchar(32) NULL,
              error_code varchar(32) NULL,
              started_at timestamptz NULL,
              heartbeat_at timestamptz NULL,
              finished_at timestamptz NULL,
              created_at timestamptz NOT NULL,
              updated_at timestamptz NOT NULL,
              CONSTRAINT security_test_runs_organization_id_id_unique UNIQUE (organization_id, id),
              CONSTRAINT security_test_runs_triggered_by_foreign FOREIGN KEY (organization_id, triggered_by) REFERENCES users (organization_id, id),
              CONSTRAINT security_test_runs_counts CHECK (passed + failed <= total),
              CONSTRAINT security_test_runs_finished_has_counts CHECK (status <> 'completed' OR passed + failed = total)
            )
            SQL);
        DB::statement('CREATE INDEX security_test_runs_organization_created_index ON security_test_runs (organization_id, created_at DESC)');
        DB::statement("CREATE UNIQUE INDEX security_test_runs_one_active_unique ON security_test_runs (organization_id) WHERE status IN ('queued', 'running')");

        DB::statement(<<<'SQL'
            CREATE TABLE security_test_results (
              id uuid PRIMARY KEY,
              organization_id uuid NOT NULL,
              run_id uuid NOT NULL,
              case_id varchar(32) NOT NULL,
              category varchar(24) NOT NULL,
              name varchar(200) NOT NULL,
              expected varchar(200) NOT NULL,
              actual varchar(200) NOT NULL,
              passed boolean NOT NULL,
              duration_ms integer NOT NULL CHECK (duration_ms >= 0),
              details jsonb NOT NULL DEFAULT '{}'::jsonb,
              created_at timestamptz NOT NULL,
              CONSTRAINT security_test_results_run_foreign FOREIGN KEY (organization_id, run_id) REFERENCES security_test_runs (organization_id, id),
              CONSTRAINT security_test_results_run_case_unique UNIQUE (run_id, case_id)
            )
            SQL);
        DB::statement('CREATE INDEX security_test_results_run_index ON security_test_results (run_id)');
        DB::statement('CREATE TRIGGER security_test_results_no_update BEFORE UPDATE OR DELETE ON security_test_results FOR EACH ROW EXECUTE FUNCTION forbid_mutation()');
        DB::statement('CREATE TRIGGER security_test_results_no_truncate BEFORE TRUNCATE ON security_test_results FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation()');

        $app = '"'.str_replace('"', '""', config()->string('database.connections.pgsql.username')).'"';
        DB::statement("GRANT SELECT, INSERT ON security_test_runs TO {$app}");
        DB::statement("GRANT UPDATE (status, total, passed, failed, ruleset_version, policy_version, error_code, started_at, heartbeat_at, finished_at, updated_at) ON security_test_runs TO {$app}");
        DB::statement("GRANT SELECT, INSERT ON security_test_results TO {$app}");
    }

    public function down(): void
    {
        // A result is a record of what was checked, and it is not thrown away by a rollback.
        if (DB::selectOne('SELECT EXISTS (SELECT 1 FROM security_test_results) AS has_rows')?->has_rows) {
            throw new RuntimeException('security_test_results has rows: they would be lost.');
        }

        DB::statement('DROP TABLE security_test_results');
        DB::statement('DROP TABLE security_test_runs');
    }
};
