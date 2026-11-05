<?php

use App\Support\Database\TestDatabaseGuard;
use Illuminate\Support\Facades\Artisan;

/*
| DB-MIG-01 (docs/test-strategy.md §13).
*/

const STEP_1_3_TABLES = ['audit_chain_heads', 'audit_logs', 'organization_settings', 'organizations', 'users'];

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

it('migrates up, rolls back completely and migrates up again', function () {
    $connection = ['--database' => TestDatabaseGuard::OWNER_CONNECTION, '--force' => true];

    resetAuditTables();

    expect(publicTables())->toBe(STEP_1_3_TABLES)
        ->and(prerequisitesExist())->toBe(['function' => 1, 'citext' => 1]);

    try {
        expect(Artisan::call('migrate:rollback', $connection + ['--step' => 6]))->toBe(0)
            ->and(publicTables())->toBe([])
            ->and(prerequisitesExist())->toBe(['function' => 0, 'citext' => 0]);
    } finally {
        $status = Artisan::call('migrate', $connection);
    }

    expect($status)->toBe(0)
        ->and(publicTables())->toBe(STEP_1_3_TABLES)
        ->and(prerequisitesExist())->toBe(['function' => 1, 'citext' => 1])
        ->and(ownerDb()->selectOne("SELECT count(*) AS n FROM pg_proc WHERE proname LIKE 'audit\\_%'")->n)->toBe(5);
});

it('AUDIT-MIG-01: rolling back only the chain step restores the step 1-1 privileges, and removes all of it', function () {
    $connection = ['--database' => TestDatabaseGuard::OWNER_CONNECTION, '--force' => true];

    resetAuditTables();

    try {
        expect(Artisan::call('migrate:rollback', $connection + ['--step' => 1]))->toBe(0)
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
    appendAudit();

    try {
        expect(fn () => Artisan::call('migrate:rollback', $connection + ['--step' => 1]))
            ->toThrow(RuntimeException::class, 'audit_logs has rows')
            ->and(publicTables())->toBe(STEP_1_3_TABLES);
    } finally {
        resetAuditTables();
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
