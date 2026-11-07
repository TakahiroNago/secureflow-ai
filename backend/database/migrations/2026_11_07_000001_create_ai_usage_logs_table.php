<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/*
| docs/database-design.md §3.13 (step 2-8). Append-only, with no prompt and no answer. Tokens are NULL when none were
| counted (the mock, a refusal, a timeout), which is not the same as zero. A workflow is reached through its analysis.
*/
return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            CREATE TABLE ai_usage_logs (
              id uuid PRIMARY KEY,
              organization_id uuid NOT NULL REFERENCES organizations (id),
              user_id uuid NOT NULL,
              analysis_request_id uuid NULL REFERENCES ai_analysis_requests (id),
              provider varchar(32) NOT NULL,
              model varchar(64) NULL,
              purpose varchar(24) NOT NULL CHECK (purpose IN ('task_generation', 'self_test')),
              prompt_tokens integer NULL CHECK (prompt_tokens >= 0),
              completion_tokens integer NULL CHECK (completion_tokens >= 0),
              total_tokens integer NULL CHECK (total_tokens >= 0),
              estimated_cost_micros bigint NULL CHECK (estimated_cost_micros >= 0),
              latency_ms integer NULL CHECK (latency_ms >= 0),
              status varchar(16) NOT NULL CHECK (status IN ('success', 'error', 'timeout', 'rate_limited', 'budget_blocked', 'invalid_output')),
              error_code varchar(64) NULL,
              provider_request_id varchar(128) NULL,
              created_at timestamptz NOT NULL,
              CONSTRAINT ai_usage_logs_user_foreign FOREIGN KEY (organization_id, user_id) REFERENCES users (organization_id, id)
            )
            SQL);
        DB::statement('CREATE INDEX ai_usage_logs_organization_created_index ON ai_usage_logs (organization_id, created_at)');
        DB::statement('CREATE INDEX ai_usage_logs_user_created_index ON ai_usage_logs (user_id, created_at)');
        DB::statement('CREATE TRIGGER ai_usage_logs_no_update BEFORE UPDATE OR DELETE ON ai_usage_logs FOR EACH ROW EXECUTE FUNCTION forbid_mutation()');
        DB::statement('CREATE TRIGGER ai_usage_logs_no_truncate BEFORE TRUNCATE ON ai_usage_logs FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation()');

        $app = '"'.str_replace('"', '""', config()->string('database.connections.pgsql.username')).'"';
        DB::statement("GRANT SELECT, INSERT ON ai_usage_logs TO {$app}");
    }

    public function down(): void
    {
        // No row comes back under --pretend.
        if (DB::selectOne('SELECT EXISTS (SELECT 1 FROM ai_usage_logs) AS has_rows')?->has_rows) {
            throw new RuntimeException('ai_usage_logs has rows: refusing to drop an append-only table.');
        }

        DB::statement('DROP TABLE ai_usage_logs');
    }
};
