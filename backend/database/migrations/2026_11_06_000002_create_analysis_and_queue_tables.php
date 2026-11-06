<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/*
| docs/database-design.md §3.4, §3.5, §3.15, §4.2 (step 1-6).
|
| Masking arrives in step 2-1, and the mock AI does not use the input, so no input is stored until then:
| input_masked stays NULL, and a NULL source_input_masked means "not stored".
|
| jobs lives in this database so that a job commits together with the row it is for. The scan columns get
| their foreign keys in step 2-3, with security_scans.
*/
return new class extends Migration
{
    public function up(): void
    {
        DB::statement('ALTER TABLE workflows ALTER COLUMN source_input_masked DROP NOT NULL');

        DB::statement(<<<'SQL'
            CREATE TABLE ai_analysis_requests (
              id uuid PRIMARY KEY,
              organization_id uuid NOT NULL,
              user_id uuid NOT NULL,
              status varchar(16) NOT NULL CHECK (status IN ('queued', 'processing', 'succeeded', 'blocked', 'failed')),
              input_masked text NULL,
              input_char_count integer NOT NULL CHECK (input_char_count >= 0),
              input_scan_id uuid NULL,
              output_scan_id uuid NULL,
              workflow_id uuid NULL,
              error_code varchar(64) NULL,
              started_at timestamptz NULL,
              heartbeat_at timestamptz NULL,
              finished_at timestamptz NULL,
              created_at timestamptz NOT NULL,
              updated_at timestamptz NOT NULL,
              CONSTRAINT ai_analysis_requests_workflow_unique UNIQUE (workflow_id),
              CONSTRAINT ai_analysis_requests_user_foreign FOREIGN KEY (organization_id, user_id) REFERENCES users (organization_id, id),
              CONSTRAINT ai_analysis_requests_workflow_foreign FOREIGN KEY (organization_id, workflow_id) REFERENCES workflows (organization_id, id),
              CONSTRAINT ai_analysis_requests_success_has_workflow CHECK ((status = 'succeeded') = (workflow_id IS NOT NULL))
            )
            SQL);
        DB::statement('CREATE INDEX ai_analysis_requests_user_created_index ON ai_analysis_requests (organization_id, user_id, created_at DESC)');
        DB::statement("CREATE INDEX ai_analysis_requests_unfinished_index ON ai_analysis_requests (status, created_at) WHERE status IN ('queued', 'processing')");

        DB::statement(<<<'SQL'
            CREATE TABLE jobs (
              id bigserial PRIMARY KEY,
              queue varchar(255) NOT NULL,
              payload text NOT NULL,
              attempts smallint NOT NULL,
              reserved_at integer NULL,
              available_at integer NOT NULL,
              created_at integer NOT NULL
            )
            SQL);
        DB::statement('CREATE INDEX jobs_queue_index ON jobs (queue)');

        DB::statement(<<<'SQL'
            CREATE TABLE failed_jobs (
              id bigserial PRIMARY KEY,
              uuid varchar(255) NOT NULL UNIQUE,
              connection text NOT NULL,
              queue text NOT NULL,
              payload text NOT NULL,
              exception text NOT NULL,
              failed_at timestamptz NOT NULL DEFAULT now()
            )
            SQL);

        $app = '"'.str_replace('"', '""', config()->string('database.connections.pgsql.username')).'"';
        DB::statement("GRANT SELECT, INSERT ON ai_analysis_requests TO {$app}");
        DB::statement("GRANT UPDATE (status, input_masked, input_scan_id, output_scan_id, workflow_id, error_code, started_at, heartbeat_at, finished_at, updated_at) ON ai_analysis_requests TO {$app}");
        DB::statement("GRANT SELECT, INSERT, UPDATE, DELETE ON jobs TO {$app}");
        DB::statement("GRANT SELECT, INSERT, DELETE ON failed_jobs TO {$app}");
        DB::statement("GRANT USAGE ON SEQUENCE jobs_id_seq, failed_jobs_id_seq TO {$app}");
    }

    public function down(): void
    {
        // No row comes back under --pretend.
        if (DB::selectOne('SELECT EXISTS (SELECT 1 FROM workflows WHERE source_input_masked IS NULL) AS has_rows')?->has_rows) {
            throw new RuntimeException('workflows has rows with no stored input: NOT NULL cannot come back.');
        }

        DB::statement('DROP TABLE failed_jobs');
        DB::statement('DROP TABLE jobs');
        DB::statement('DROP TABLE ai_analysis_requests');
        DB::statement('ALTER TABLE workflows ALTER COLUMN source_input_masked SET NOT NULL');
    }
};
