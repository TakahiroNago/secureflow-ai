<?php

use App\Models\User;
use App\Support\Database\TestDatabaseGuard;
use Illuminate\Support\Facades\Artisan;

/*
| DB-MIG-01 (docs/test-strategy.md §13).
*/

const STEP_1_3_TABLES = ['audit_chain_heads', 'audit_logs', 'organization_settings', 'organizations', 'users'];

const STEP_1_5_TABLES = ['approvals', 'audit_chain_heads', 'audit_logs', 'organization_settings', 'organizations', 'users', 'workflow_executions', 'workflow_revisions', 'workflow_tasks', 'workflows'];

const STEP_1_6_TABLES = ['ai_analysis_requests', 'approvals', 'audit_chain_heads', 'audit_logs', 'failed_jobs', 'jobs', 'organization_settings', 'organizations', 'users', 'workflow_executions', 'workflow_revisions', 'workflow_tasks', 'workflows'];

const STEP_2_3_TABLES = ['ai_analysis_requests', 'approvals', 'audit_chain_heads', 'audit_logs', 'failed_jobs', 'jobs', 'organization_settings', 'organizations', 'security_findings', 'security_scans', 'users', 'workflow_executions', 'workflow_revisions', 'workflow_tasks', 'workflows'];

const LATEST_TABLES = ['ai_analysis_requests', 'ai_usage_logs', 'approvals', 'audit_chain_heads', 'audit_logs', 'failed_jobs', 'jobs', 'organization_settings', 'organizations', 'security_findings', 'security_scans', 'security_test_results', 'security_test_runs', 'users', 'workflow_executions', 'workflow_revisions', 'workflow_tasks', 'workflows'];

function publicTables(): array
{
    $rows = ownerDb()->select("SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> 'migrations' ORDER BY tablename");

    return array_map(fn (object $row) => $row->tablename, $rows);
}

function prerequisitesExist(): array
{
    return [
        'function' => ownerDb()->selectOne("SELECT count(*) AS n FROM pg_proc WHERE proname = 'forbid_mutation'")->n,
        'citext' => ownerDb()->selectOne("SELECT count(*) AS n FROM pg_extension WHERE extname = 'citext'")->n,
    ];
}

// The steps that roll back through the named migration, counted from the latest: a new migration moves them all by one.
function stepsBackThrough(string $migration): int
{
    $names = array_map('basename', glob(database_path('migrations/*.php')) ?: []);

    return count(array_filter($names, fn (string $name) => strcmp($name, $migration) >= 0));
}

it('migrates up, rolls back completely and migrates up again', function () {
    $connection = ['--database' => TestDatabaseGuard::OWNER_CONNECTION, '--force' => true];

    resetAuditTables();
    resetWorkflowTables();

    expect(publicTables())->toBe(LATEST_TABLES)
        ->and(prerequisitesExist())->toBe(['function' => 1, 'citext' => 1]);

    try {
        expect(Artisan::call('migrate:rollback', $connection + ['--step' => stepsBackThrough('2026_11_04_000001')]))->toBe(0)
            ->and(publicTables())->toBe([])
            ->and(prerequisitesExist())->toBe(['function' => 0, 'citext' => 0]);
    } finally {
        $status = Artisan::call('migrate', $connection);
    }

    expect($status)->toBe(0)
        ->and(publicTables())->toBe(LATEST_TABLES)
        ->and(prerequisitesExist())->toBe(['function' => 1, 'citext' => 1])
        ->and(ownerDb()->selectOne("SELECT count(*) AS n FROM pg_proc WHERE proname LIKE 'audit\\_%'")->n)->toBe(5);
});

it('AUDIT-MIG-01: rolling back only the chain step restores the step 1-1 privileges, and removes all of it', function () {
    $connection = ['--database' => TestDatabaseGuard::OWNER_CONNECTION, '--force' => true];

    resetAuditTables();
    resetWorkflowTables();

    try {
        expect(Artisan::call('migrate:rollback', $connection + ['--step' => stepsBackThrough('2026_11_04_000006')]))->toBe(0)
            ->and(publicTables())->toBe(['audit_logs', 'organization_settings', 'organizations', 'users'])
            ->and(ownerDb()->selectOne("SELECT count(*) AS n FROM pg_proc WHERE proname LIKE 'audit\\_%'")->n)->toBe(0)
            ->and(appDb()->selectOne("SELECT has_column_privilege(current_user, 'audit_logs', 'event_id', 'INSERT') AS granted")->granted)->toBeTrue();
    } finally {
        $status = Artisan::call('migrate', $connection);
    }

    expect($status)->toBe(0)
        ->and(appDb()->selectOne("SELECT has_column_privilege(current_user, 'audit_logs', 'event_id', 'INSERT') AS granted")->granted)->toBeFalse();
});

it('AUDIT-MIG-01: refuses to run in either direction while audit_logs has rows', function () {
    $connection = ['--database' => TestDatabaseGuard::OWNER_CONNECTION, '--force' => true];

    resetAuditTables();
    resetWorkflowTables();
    appendAudit();

    try {
        expect(fn () => Artisan::call('migrate:rollback', $connection + ['--step' => stepsBackThrough('2026_11_04_000006')]))
            ->toThrow(RuntimeException::class, 'audit_logs has rows')
            ->and(publicTables())->toBe(STEP_1_3_TABLES);
    } finally {
        resetAuditTables();
        Artisan::call('migrate', $connection);
    }

    expect(publicTables())->toBe(LATEST_TABLES);
});

it('refuses to restore NOT NULL while a workflow has no stored input', function () {
    $connection = ['--database' => TestDatabaseGuard::OWNER_CONNECTION, '--force' => true];

    resetWorkflowTables();
    $creator = User::factory()->create();
    workflowOf($creator, ['source_input_masked' => null]);

    try {
        expect(fn () => Artisan::call('migrate:rollback', $connection + ['--step' => stepsBackThrough('2026_11_06_000002')]))
            ->toThrow(RuntimeException::class, 'no stored input')
            ->and(publicTables())->toBe(STEP_1_6_TABLES);
    } finally {
        Artisan::call('migrate', $connection);
        resetWorkflowTables();
        ownerDb()->table('users')->where('id', $creator->id)->delete();
        ownerDb()->table('organizations')->where('id', $creator->organization_id)->delete();
    }
});

it('refuses to drop the workflow tables while a revision exists, and keeps them whole', function () {
    $connection = ['--database' => TestDatabaseGuard::OWNER_CONNECTION, '--force' => true];

    resetWorkflowTables();
    $creator = User::factory()->create();
    $workflow = workflowOf($creator);

    try {
        // The step before this one had no scans, so an unscanned revision is the row it can have.
        Artisan::call('migrate:rollback', $connection + ['--step' => stepsBackThrough('2026_11_06_000003')]);
        insertRevision(appDb(), $workflow, ['scan_id' => null]);

        // From the step 1-6 state: its own step, then the workflow step refuses.
        expect(fn () => Artisan::call('migrate:rollback', $connection + ['--step' => 2]))
            ->toThrow(RuntimeException::class, 'workflow_revisions has rows')
            ->and(publicTables())->toBe(STEP_1_5_TABLES);
    } finally {
        Artisan::call('migrate', $connection);
        resetWorkflowTables();
        ownerDb()->table('users')->where('id', $creator->id)->delete();
        ownerDb()->table('organizations')->where('id', $creator->organization_id)->delete();
    }
});

it('rolls the workflow step back completely, including the key added to users', function () {
    $connection = ['--database' => TestDatabaseGuard::OWNER_CONNECTION, '--force' => true];

    resetWorkflowTables();

    $objects = fn () => [
        'functions' => ownerDb()->selectOne("SELECT count(*) AS n FROM pg_proc WHERE proname LIKE 'approvals\\_%'")->n,
        'users_key' => ownerDb()->selectOne("SELECT count(*) AS n FROM pg_constraint WHERE conname = 'users_organization_id_id_unique'")->n,
    ];

    expect($objects())->toBe(['functions' => 2, 'users_key' => 1]);

    try {
        expect(Artisan::call('migrate:rollback', $connection + ['--step' => stepsBackThrough('2026_11_06_000001')]))->toBe(0)
            ->and(publicTables())->toBe(STEP_1_3_TABLES)
            ->and($objects())->toBe(['functions' => 0, 'users_key' => 0]);
    } finally {
        Artisan::call('migrate', $connection);
    }

    expect($objects())->toBe(['functions' => 2, 'users_key' => 1]);
});

it('keeps rows from before step 2-3 as they are, and refuses new ones like them', function () {
    $connection = ['--database' => TestDatabaseGuard::OWNER_CONNECTION, '--force' => true];

    resetWorkflowTables();
    $creator = User::factory()->create();
    $workflow = workflowOf($creator);

    try {
        expect(Artisan::call('migrate:rollback', $connection + ['--step' => stepsBackThrough('2026_11_06_000003')]))->toBe(0);
        $revision = insertRevision(appDb(), $workflow, ['scan_id' => null]);
    } finally {
        $status = Artisan::call('migrate', $connection);
    }

    $old = appDb()->table('workflow_revisions')->where('id', $revision)->first();

    expect($status)->toBe(0)
        ->and($old->scan_id)->toBeNull()
        ->and($old->scan_decision)->toBeNull()
        ->and(sqlStateFrom(dbError(appDb(), fn ($db) => insertRevision($db, $workflow, ['revision_no' => 2, 'scan_id' => null]))))->toBe('23514');

    resetWorkflowTables();
    ownerDb()->table('users')->where('id', $creator->id)->delete();
    ownerDb()->table('organizations')->where('id', $creator->organization_id)->delete();
});

it('refuses to roll back while a scan exists, because the record would be lost', function () {
    $connection = ['--database' => TestDatabaseGuard::OWNER_CONNECTION, '--force' => true];

    resetWorkflowTables();
    $creator = User::factory()->create();
    insertScan(appDb(), $creator->organization_id);

    try {
        expect(fn () => Artisan::call('migrate:rollback', $connection + ['--step' => stepsBackThrough('2026_11_06_000003')]))
            ->toThrow(RuntimeException::class, 'security_scans has rows')
            ->and(publicTables())->toBe(STEP_2_3_TABLES);
    } finally {
        // The table of this step went first, and has to be back before the tables can be emptied.
        Artisan::call('migrate', $connection);
        resetWorkflowTables();
        ownerDb()->table('users')->where('id', $creator->id)->delete();
        ownerDb()->table('organizations')->where('id', $creator->organization_id)->delete();
    }
});

it('AUDIT-MIG-01: does not touch the id sequence', function () {
    $source = (string) file_get_contents(database_path('migrations/2026_11_04_000006_add_hash_chain_to_audit_logs.php'));

    expect($source)->not->toContain('setval')->not->toContain('nextval')->not->toContain('RESTART');
});

it('restores the privileges after migrating up again', function () {
    $row = appDb()->selectOne(
        "SELECT has_function_privilege(current_user, 'public.audit_append(uuid, uuid, text, uuid, text, text, uuid, text, text, inet, uuid, jsonb)', 'EXECUTE') AS granted"
    );

    expect($row->granted)->toBeTrue();
});

it('creates audit_logs with exactly the designed columns', function () {
    $rows = ownerDb()->select(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'audit_logs' ORDER BY ordinal_position"
    );

    expect(array_map(fn (object $row) => $row->column_name, $rows))->toBe([
        'id', 'event_id', 'organization_id', 'actor_type', 'actor_user_id', 'event_type',
        'resource_type', 'resource_id', 'result', 'severity', 'ip_address', 'request_id',
        'metadata', 'occurred_at', 'prev_hash', 'hash', 'chain_id', 'chain_seq', 'hash_version',
    ]);
});

it('makes audit_logs.id an always-generated identity column', function () {
    $row = ownerDb()->selectOne(
        "SELECT is_identity, identity_generation FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'audit_logs' AND column_name = 'id'"
    );

    expect($row->is_identity)->toBe('YES')->and($row->identity_generation)->toBe('ALWAYS');
});

it('creates the designed indexes', function (string $index, string $definition) {
    $row = ownerDb()->selectOne('SELECT indexdef FROM pg_indexes WHERE schemaname = ? AND indexname = ?', ['public', $index]);

    expect($row->indexdef)->toContain($definition);
})->with([
    ['users_organization_id_index', '(organization_id)'],
    ['audit_logs_organization_occurred_index', '(organization_id, occurred_at DESC)'],
    ['audit_logs_organization_event_occurred_index', '(organization_id, event_type, occurred_at DESC)'],
    ['audit_logs_actor_occurred_index', '(actor_user_id, occurred_at DESC)'],
]);

it('gives audit_logs no foreign keys, so logs outlive what they describe', function () {
    $row = ownerDb()->selectOne("SELECT count(*) AS n FROM pg_constraint WHERE conrelid = 'audit_logs'::regclass AND contype = 'f'");

    expect($row->n)->toBe(0);
});

it('uses timestamptz for every timestamp', function () {
    $row = ownerDb()->selectOne(
        "SELECT count(*) AS n FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name <> 'migrations'
           AND data_type = 'timestamp without time zone'"
    );

    expect($row->n)->toBe(0);
});
