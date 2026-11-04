<?php

use App\Support\Database\TestDatabaseGuard;
use Illuminate\Support\Facades\Artisan;

/*
| DB-MIG-01 (docs/test-strategy.md §13).
*/

const STEP_1_1_TABLES = ['audit_logs', 'organization_settings', 'organizations', 'users'];

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

    expect(publicTables())->toBe(STEP_1_1_TABLES)
        ->and(prerequisitesExist())->toBe(['function' => 1, 'citext' => 1]);

    try {
        expect(Artisan::call('migrate:rollback', $connection + ['--step' => 5]))->toBe(0)
            ->and(publicTables())->toBe([])
            ->and(prerequisitesExist())->toBe(['function' => 0, 'citext' => 0]);
    } finally {
        $status = Artisan::call('migrate', $connection);
    }

    expect($status)->toBe(0)
        ->and(publicTables())->toBe(STEP_1_1_TABLES)
        ->and(prerequisitesExist())->toBe(['function' => 1, 'citext' => 1]);
});

it('restores the privileges after migrating up again', function () {
    $row = appDb()->selectOne("SELECT has_column_privilege(current_user, 'audit_logs', 'event_id', 'INSERT') AS granted");

    expect($row->granted)->toBeTrue();
});

it('creates audit_logs with exactly the designed columns and no chain columns', function () {
    $rows = ownerDb()->select(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'audit_logs' ORDER BY ordinal_position"
    );

    expect(array_map(fn (object $row) => $row->column_name, $rows))->toBe([
        'id', 'event_id', 'organization_id', 'actor_type', 'actor_user_id', 'event_type',
        'resource_type', 'resource_id', 'result', 'severity', 'ip_address', 'request_id',
        'metadata', 'occurred_at', 'prev_hash', 'hash',
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
