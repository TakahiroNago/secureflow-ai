<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/*
| docs/database-design.md §3.10, §3.11 (step 2-3).
|
| New rows must point at a scan, and rows from before this step stay as they are: NOT VALID checks new and
| changed rows only. A revision is never changed, and those older rows go on meaning "not scanned".
*/
return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            CREATE TABLE security_scans (
              id uuid PRIMARY KEY,
              organization_id uuid NOT NULL,
              user_id uuid NULL,
              target_type varchar(16) NOT NULL CHECK (target_type IN ('input', 'output', 'revision', 'self_test')),
              target_id uuid NULL,
              ruleset_version varchar(32) NOT NULL,
              max_severity varchar(8) NULL CHECK (max_severity IN ('low', 'medium', 'high', 'critical')),
              decision varchar(8) NOT NULL CHECK (decision IN ('allow', 'warn', 'block')),
              block_reason varchar(32) NULL,
              masking_status varchar(16) NOT NULL CHECK (masking_status IN ('not_required', 'masked', 'failed')),
              findings_count integer NOT NULL CHECK (findings_count >= 0),
              duration_ms integer NOT NULL CHECK (duration_ms >= 0),
              created_at timestamptz NOT NULL,
              CONSTRAINT security_scans_organization_id_unique UNIQUE (organization_id, id),
              CONSTRAINT security_scans_decision_unique UNIQUE (organization_id, id, decision),
              CONSTRAINT security_scans_user_foreign FOREIGN KEY (organization_id, user_id) REFERENCES users (organization_id, id),
              CONSTRAINT security_scans_failed_masking_blocks CHECK (masking_status <> 'failed' OR decision = 'block'),
              CONSTRAINT security_scans_block_has_reason CHECK ((decision = 'block') = (block_reason IS NOT NULL))
            )
            SQL);
        DB::statement('CREATE INDEX security_scans_organization_created_index ON security_scans (organization_id, created_at DESC)');
        DB::statement('CREATE INDEX security_scans_user_created_index ON security_scans (organization_id, user_id, created_at DESC)');
        DB::statement('CREATE TRIGGER security_scans_no_update BEFORE UPDATE OR DELETE ON security_scans FOR EACH ROW EXECUTE FUNCTION forbid_mutation()');
        DB::statement('CREATE TRIGGER security_scans_no_truncate BEFORE TRUNCATE ON security_scans FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation()');

        DB::statement(<<<'SQL'
            CREATE TABLE security_findings (
              id uuid PRIMARY KEY,
              organization_id uuid NOT NULL,
              scan_id uuid NOT NULL,
              category varchar(24) NOT NULL CHECK (category IN ('pii', 'secret', 'injection', 'schema', 'forbidden_action', 'permission_mismatch', 'markup', 'canary', 'masking')),
              rule_id varchar(64) NOT NULL,
              severity varchar(8) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
              action varchar(16) NOT NULL CHECK (action IN ('record', 'mask_continue', 'warn', 'block')),
              message varchar(300) NOT NULL,
              masked_excerpt varchar(200) NULL,
              field_path varchar(64) NULL,
              position_start integer NULL CHECK (position_start >= 0),
              position_end integer NULL CHECK (position_end >= 0),
              status varchar(16) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved', 'false_positive')),
              status_note varchar(500) NULL,
              status_changed_by uuid NULL,
              status_changed_at timestamptz NULL,
              created_at timestamptz NOT NULL,
              updated_at timestamptz NOT NULL,
              CONSTRAINT security_findings_scan_foreign FOREIGN KEY (organization_id, scan_id) REFERENCES security_scans (organization_id, id),
              CONSTRAINT security_findings_changed_by_foreign FOREIGN KEY (organization_id, status_changed_by) REFERENCES users (organization_id, id),
              CONSTRAINT security_findings_no_excerpt_of_a_secret CHECK (category NOT IN ('secret', 'masking') OR masked_excerpt IS NULL),
              CONSTRAINT security_findings_excerpt_length CHECK (char_length(masked_excerpt) <= 80),
              CONSTRAINT security_findings_block_keeps_no_excerpt CHECK (action <> 'block' OR masked_excerpt IS NULL)
            )
            SQL);
        DB::statement('CREATE INDEX security_findings_scan_index ON security_findings (scan_id)');
        DB::statement('CREATE INDEX security_findings_status_index ON security_findings (organization_id, status, severity)');
        DB::statement('CREATE INDEX security_findings_created_index ON security_findings (organization_id, created_at DESC)');

        // The decision is part of the key, so a revision cannot say anything other than what its scan found.
        DB::statement('ALTER TABLE workflow_revisions ADD CONSTRAINT workflow_revisions_scan_foreign FOREIGN KEY (organization_id, scan_id, scan_decision) REFERENCES security_scans (organization_id, id, decision)');
        DB::statement('ALTER TABLE workflow_revisions ADD CONSTRAINT workflow_revisions_new_rows_scanned CHECK (scan_id IS NOT NULL) NOT VALID');

        DB::statement('ALTER TABLE ai_analysis_requests ADD CONSTRAINT ai_analysis_requests_input_scan_foreign FOREIGN KEY (organization_id, input_scan_id) REFERENCES security_scans (organization_id, id)');
        DB::statement('ALTER TABLE ai_analysis_requests ADD CONSTRAINT ai_analysis_requests_output_scan_foreign FOREIGN KEY (organization_id, output_scan_id) REFERENCES security_scans (organization_id, id)');
        DB::statement('ALTER TABLE ai_analysis_requests ADD CONSTRAINT ai_analysis_requests_new_rows_scanned CHECK (input_scan_id IS NOT NULL) NOT VALID');
        DB::statement("ALTER TABLE ai_analysis_requests ADD CONSTRAINT ai_analysis_requests_success_is_scanned CHECK (status <> 'succeeded' OR output_scan_id IS NOT NULL) NOT VALID");
        DB::statement("ALTER TABLE ai_analysis_requests ADD CONSTRAINT ai_analysis_requests_finished_keeps_no_input CHECK (status IN ('queued', 'processing') OR input_masked IS NULL)");

        $app = '"'.str_replace('"', '""', config()->string('database.connections.pgsql.username')).'"';
        DB::statement("GRANT SELECT, INSERT ON security_scans TO {$app}");
        DB::statement("GRANT SELECT, INSERT ON security_findings TO {$app}");
        DB::statement("GRANT UPDATE (status, status_note, status_changed_by, status_changed_at, updated_at) ON security_findings TO {$app}");
    }

    public function down(): void
    {
        // A scan is a record of what was found, and it is not thrown away by a rollback. No row comes back under --pretend.
        if (DB::selectOne('SELECT EXISTS (SELECT 1 FROM security_scans) AS has_rows')?->has_rows) {
            throw new RuntimeException('security_scans has rows: they would be lost.');
        }

        DB::statement('ALTER TABLE ai_analysis_requests DROP CONSTRAINT ai_analysis_requests_finished_keeps_no_input');
        DB::statement('ALTER TABLE ai_analysis_requests DROP CONSTRAINT ai_analysis_requests_success_is_scanned');
        DB::statement('ALTER TABLE ai_analysis_requests DROP CONSTRAINT ai_analysis_requests_new_rows_scanned');
        DB::statement('ALTER TABLE ai_analysis_requests DROP CONSTRAINT ai_analysis_requests_output_scan_foreign');
        DB::statement('ALTER TABLE ai_analysis_requests DROP CONSTRAINT ai_analysis_requests_input_scan_foreign');
        DB::statement('ALTER TABLE workflow_revisions DROP CONSTRAINT workflow_revisions_new_rows_scanned');
        DB::statement('ALTER TABLE workflow_revisions DROP CONSTRAINT workflow_revisions_scan_foreign');
        DB::statement('DROP TABLE security_findings');
        DB::statement('DROP TABLE security_scans');
    }
};
