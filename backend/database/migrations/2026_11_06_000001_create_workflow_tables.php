<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/*
| docs/database-design.md §3.5 to §3.9, §4.2, §5 (step 1-5).
|
| Composite foreign keys keep every row inside its own organization and workflow, whatever the
| application does. security_scans arrives in step 2-3, so scan_id has no foreign key yet and NULL
| means "not scanned": steps 2-5 and 2-6 refuse such a revision, and step 2-3 requires it on new rows.
|
| Column-level UPDATE: id, organization_id and the creator can never change through the application.
*/
return new class extends Migration
{
    public function up(): void
    {
        DB::statement('ALTER TABLE users ADD CONSTRAINT users_organization_id_id_unique UNIQUE (organization_id, id)');

        DB::statement(<<<'SQL'
            CREATE TABLE workflows (
              id uuid PRIMARY KEY,
              organization_id uuid NOT NULL REFERENCES organizations (id),
              created_by uuid NOT NULL,
              title varchar(200) NOT NULL,
              source_input_masked text NOT NULL,
              status varchar(16) NOT NULL CHECK (status IN ('draft', 'pending', 'approved', 'running', 'completed', 'rejected', 'failed')),
              current_revision_id uuid NULL,
              max_severity varchar(8) NULL CHECK (max_severity IN ('low', 'medium', 'high', 'critical')),
              lock_version integer NOT NULL DEFAULT 0 CHECK (lock_version >= 0),
              submitted_at timestamptz NULL,
              created_at timestamptz NOT NULL,
              updated_at timestamptz NOT NULL,
              CONSTRAINT workflows_organization_id_id_unique UNIQUE (organization_id, id),
              CONSTRAINT workflows_creator_foreign FOREIGN KEY (organization_id, created_by) REFERENCES users (organization_id, id)
            )
            SQL);
        DB::statement('CREATE INDEX workflows_organization_status_index ON workflows (organization_id, status)');
        DB::statement('CREATE INDEX workflows_organization_creator_created_index ON workflows (organization_id, created_by, created_at DESC)');

        DB::statement(<<<'SQL'
            CREATE TABLE workflow_revisions (
              id uuid PRIMARY KEY,
              organization_id uuid NOT NULL,
              workflow_id uuid NOT NULL,
              revision_no integer NOT NULL CHECK (revision_no >= 1),
              plan_snapshot jsonb NOT NULL CHECK (jsonb_typeof(plan_snapshot) = 'object'),
              plan_hash char(64) NOT NULL CHECK (plan_hash ~ '^[0-9a-f]{64}$'),
              hash_version smallint NOT NULL CHECK (hash_version >= 1),
              policy_version varchar(32) NOT NULL,
              scan_id uuid NULL,
              scan_decision varchar(8) NULL CHECK (scan_decision IN ('allow', 'warn', 'block')),
              change_type varchar(16) NOT NULL CHECK (change_type IN ('ai_generated', 'user_edit', 'reopen')),
              created_by uuid NULL,
              created_at timestamptz NOT NULL,
              CONSTRAINT workflow_revisions_number_unique UNIQUE (workflow_id, revision_no),
              CONSTRAINT workflow_revisions_workflow_id_id_unique UNIQUE (workflow_id, id),
              CONSTRAINT workflow_revisions_workflow_foreign FOREIGN KEY (organization_id, workflow_id) REFERENCES workflows (organization_id, id),
              CONSTRAINT workflow_revisions_creator_foreign FOREIGN KEY (organization_id, created_by) REFERENCES users (organization_id, id),
              CONSTRAINT workflow_revisions_scan_pair CHECK ((scan_id IS NULL) = (scan_decision IS NULL))
            )
            SQL);

        // A workflow can only point at one of its own revisions.
        DB::statement(<<<'SQL'
            ALTER TABLE workflows ADD CONSTRAINT workflows_current_revision_foreign
              FOREIGN KEY (id, current_revision_id) REFERENCES workflow_revisions (workflow_id, id)
              DEFERRABLE INITIALLY DEFERRED
            SQL);

        DB::statement(<<<'SQL'
            CREATE TABLE workflow_tasks (
              id uuid PRIMARY KEY,
              organization_id uuid NOT NULL,
              workflow_id uuid NOT NULL,
              position smallint NOT NULL CHECK (position BETWEEN 1 AND 10),
              title varchar(100) NOT NULL,
              description varchar(1000) NOT NULL,
              action_type varchar(50) NOT NULL,
              steps jsonb NOT NULL CHECK (jsonb_typeof(steps) = 'array'),
              priority varchar(8) NOT NULL CHECK (priority IN ('low', 'medium', 'high')),
              target_data varchar(500) NOT NULL,
              impact_summary varchar(1000) NOT NULL,
              derived_permissions jsonb NOT NULL CHECK (jsonb_typeof(derived_permissions) = 'array'),
              ai_claimed_permissions jsonb NOT NULL CHECK (jsonb_typeof(ai_claimed_permissions) = 'array'),
              policy_decision varchar(16) NOT NULL CHECK (policy_decision IN ('allowed', 'forbidden')),
              created_at timestamptz NOT NULL,
              updated_at timestamptz NOT NULL,
              CONSTRAINT workflow_tasks_position_unique UNIQUE (workflow_id, position) DEFERRABLE INITIALLY IMMEDIATE,
              CONSTRAINT workflow_tasks_workflow_foreign FOREIGN KEY (organization_id, workflow_id) REFERENCES workflows (organization_id, id)
            )
            SQL);

        DB::statement(<<<'SQL'
            CREATE TABLE approvals (
              id uuid PRIMARY KEY,
              organization_id uuid NOT NULL,
              workflow_id uuid NOT NULL,
              workflow_revision_id uuid NOT NULL,
              plan_hash char(64) NOT NULL CHECK (plan_hash ~ '^[0-9a-f]{64}$'),
              decision varchar(8) NOT NULL CHECK (decision IN ('approved', 'rejected')),
              decided_by uuid NOT NULL,
              comment varchar(1000) NULL,
              acknowledged_risks boolean NOT NULL,
              created_at timestamptz NOT NULL,
              CONSTRAINT approvals_revision_unique UNIQUE (workflow_revision_id),
              CONSTRAINT approvals_id_revision_unique UNIQUE (id, workflow_revision_id),
              CONSTRAINT approvals_workflow_foreign FOREIGN KEY (organization_id, workflow_id) REFERENCES workflows (organization_id, id),
              CONSTRAINT approvals_revision_foreign FOREIGN KEY (workflow_id, workflow_revision_id) REFERENCES workflow_revisions (workflow_id, id),
              CONSTRAINT approvals_decider_foreign FOREIGN KEY (organization_id, decided_by) REFERENCES users (organization_id, id)
            )
            SQL);

        DB::statement(<<<'SQL'
            CREATE TABLE workflow_executions (
              id uuid PRIMARY KEY,
              organization_id uuid NOT NULL,
              workflow_id uuid NOT NULL,
              approval_id uuid NOT NULL,
              workflow_revision_id uuid NOT NULL,
              idempotency_key varchar(100) NOT NULL,
              requested_by uuid NOT NULL,
              status varchar(16) NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
              started_at timestamptz NULL,
              heartbeat_at timestamptz NULL,
              finished_at timestamptz NULL,
              result jsonb NULL,
              error_code varchar(64) NULL,
              created_at timestamptz NOT NULL,
              updated_at timestamptz NOT NULL,
              CONSTRAINT workflow_executions_approval_unique UNIQUE (approval_id),
              CONSTRAINT workflow_executions_idempotency_unique UNIQUE (organization_id, idempotency_key),
              CONSTRAINT workflow_executions_workflow_foreign FOREIGN KEY (organization_id, workflow_id) REFERENCES workflows (organization_id, id),
              CONSTRAINT workflow_executions_revision_foreign FOREIGN KEY (workflow_id, workflow_revision_id) REFERENCES workflow_revisions (workflow_id, id),
              CONSTRAINT workflow_executions_approval_foreign FOREIGN KEY (approval_id, workflow_revision_id) REFERENCES approvals (id, workflow_revision_id),
              CONSTRAINT workflow_executions_requester_foreign FOREIGN KEY (organization_id, requested_by) REFERENCES users (organization_id, id)
            )
            SQL);
        DB::statement("CREATE UNIQUE INDEX workflow_executions_one_active_unique ON workflow_executions (workflow_id) WHERE status IN ('queued', 'running')");

        foreach (['workflow_revisions', 'approvals'] as $table) {
            DB::statement("CREATE TRIGGER {$table}_no_update BEFORE UPDATE OR DELETE ON {$table} FOR EACH ROW EXECUTE FUNCTION forbid_mutation()");
            DB::statement("CREATE TRIGGER {$table}_no_truncate BEFORE TRUNCATE ON {$table} FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation()");
        }

        // Runs as the application role, which can read both tables. The share lock holds the row until
        // the approval commits, so a role change cannot slip between this check and the commit.
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION approvals_forbid_self_approval() RETURNS trigger
            LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
            BEGIN
              IF EXISTS (SELECT 1 FROM workflows WHERE id = NEW.workflow_id AND created_by = NEW.decided_by) THEN
                RAISE EXCEPTION 'the creator of a workflow cannot decide on it' USING ERRCODE = 'insufficient_privilege';
              END IF;
              RETURN NEW;
            END $$
            SQL);
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION approvals_require_admin() RETURNS trigger
            LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
            BEGIN
              PERFORM 1 FROM users
                WHERE id = NEW.decided_by AND organization_id = NEW.organization_id AND role = 'admin' AND is_active
                FOR SHARE;
              IF NOT FOUND THEN
                RAISE EXCEPTION 'only an active admin of the organization can decide' USING ERRCODE = 'insufficient_privilege';
              END IF;
              RETURN NEW;
            END $$
            SQL);
        DB::statement('REVOKE ALL ON FUNCTION approvals_forbid_self_approval() FROM PUBLIC');
        DB::statement('REVOKE ALL ON FUNCTION approvals_require_admin() FROM PUBLIC');
        DB::statement('CREATE TRIGGER approvals_forbid_self_approval BEFORE INSERT ON approvals FOR EACH ROW EXECUTE FUNCTION approvals_forbid_self_approval()');
        DB::statement('CREATE TRIGGER approvals_require_admin BEFORE INSERT ON approvals FOR EACH ROW EXECUTE FUNCTION approvals_require_admin()');

        $app = '"'.str_replace('"', '""', config()->string('database.connections.pgsql.username')).'"';
        DB::statement("GRANT SELECT, INSERT ON workflows, workflow_revisions, workflow_tasks, approvals, workflow_executions TO {$app}");
        DB::statement("GRANT UPDATE (title, status, current_revision_id, max_severity, lock_version, submitted_at, updated_at) ON workflows TO {$app}");
        DB::statement("GRANT UPDATE (position, title, description, action_type, steps, priority, target_data, impact_summary, derived_permissions, ai_claimed_permissions, policy_decision, updated_at), DELETE ON workflow_tasks TO {$app}");
        DB::statement("GRANT UPDATE (status, started_at, heartbeat_at, finished_at, result, error_code, updated_at) ON workflow_executions TO {$app}");
    }

    public function down(): void
    {
        // Revisions and approvals are the record of what was decided. Dropping them must be a choice.
        foreach (['workflow_revisions', 'approvals'] as $table) {
            // No row comes back under --pretend.
            if (DB::selectOne("SELECT EXISTS (SELECT 1 FROM {$table}) AS has_rows")?->has_rows) {
                throw new RuntimeException("{$table} has rows: refusing to drop an append-only table.");
            }
        }

        DB::statement('ALTER TABLE workflows DROP CONSTRAINT workflows_current_revision_foreign');
        DB::statement('DROP TABLE workflow_executions');
        DB::statement('DROP TABLE approvals');
        DB::statement('DROP TABLE workflow_tasks');
        DB::statement('DROP TABLE workflow_revisions');
        DB::statement('DROP TABLE workflows');
        DB::statement('DROP FUNCTION approvals_forbid_self_approval()');
        DB::statement('DROP FUNCTION approvals_require_admin()');
        DB::statement('ALTER TABLE users DROP CONSTRAINT users_organization_id_id_unique');
    }
};
