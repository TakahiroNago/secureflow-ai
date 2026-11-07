<?php

use App\Support\Database\TestDatabaseGuard;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;

/*
| DB-PRIV-01, DB-ROLE-01 (docs/test-strategy.md §13, docs/database-design.md §4).
| The privileges must match the design exactly, in both directions.
*/

const ALL_TABLE_PRIVILEGES = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'];

function grantedTablePrivileges(string $table): array
{
    return array_values(array_filter(ALL_TABLE_PRIVILEGES, fn (string $privilege) => appDb()
        ->selectOne('SELECT has_table_privilege(current_user, ?, ?) AS granted', [$table, $privilege])
        ->granted));
}

it('grants the application role exactly the designed table privileges', function (string $table, array $expected) {
    expect(grantedTablePrivileges($table))->toBe($expected);
})->with([
    'organizations' => ['organizations', ['SELECT', 'INSERT', 'UPDATE']],
    'organization_settings' => ['organization_settings', ['SELECT', 'INSERT', 'UPDATE']],
    'users' => ['users', ['SELECT', 'INSERT', 'UPDATE']],
    'audit_logs' => ['audit_logs', ['SELECT']],
    'audit_chain_heads' => ['audit_chain_heads', ['SELECT']],
    'migrations' => ['migrations', []],
    // UPDATE on these is column by column: see the next test.
    'workflows' => ['workflows', ['SELECT', 'INSERT']],
    'workflow_tasks' => ['workflow_tasks', ['SELECT', 'INSERT', 'DELETE']],
    'workflow_executions' => ['workflow_executions', ['SELECT', 'INSERT']],
    'workflow_revisions' => ['workflow_revisions', ['SELECT', 'INSERT']],
    'approvals' => ['approvals', ['SELECT', 'INSERT']],
    'ai_analysis_requests' => ['ai_analysis_requests', ['SELECT', 'INSERT']],
    'ai_usage_logs' => ['ai_usage_logs', ['SELECT', 'INSERT']],
    'jobs' => ['jobs', ['SELECT', 'INSERT', 'UPDATE', 'DELETE']],
    'failed_jobs' => ['failed_jobs', ['SELECT', 'INSERT', 'DELETE']],
    'security_scans' => ['security_scans', ['SELECT', 'INSERT']],
    'security_findings' => ['security_findings', ['SELECT', 'INSERT']],
]);

it('grants UPDATE only on the columns that may change', function (string $table, array $expected) {
    $rows = appDb()->select(
        "SELECT column_name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = ?
           AND has_column_privilege(current_user, table_name::text, column_name::text, 'UPDATE')
         ORDER BY column_name",
        [$table],
    );

    $expected = array_values($expected);
    sort($expected);

    expect(array_map(fn (object $row) => $row->column_name, $rows))->toBe($expected);
})->with([
    'workflows' => ['workflows', ['title', 'status', 'current_revision_id', 'max_severity', 'lock_version', 'submitted_at', 'updated_at']],
    'workflow_tasks' => ['workflow_tasks', ['position', 'title', 'description', 'action_type', 'steps', 'priority', 'target_data', 'impact_summary', 'derived_permissions', 'ai_claimed_permissions', 'policy_decision', 'updated_at']],
    'workflow_executions' => ['workflow_executions', ['status', 'started_at', 'heartbeat_at', 'finished_at', 'result', 'error_code', 'updated_at']],
    'workflow_revisions' => ['workflow_revisions', []],
    'approvals' => ['approvals', []],
    'security_scans' => ['security_scans', []],
    'security_findings' => ['security_findings', ['status', 'status_note', 'status_changed_by', 'status_changed_at', 'updated_at']],
    'ai_analysis_requests' => ['ai_analysis_requests', ['status', 'input_masked', 'input_scan_id', 'output_scan_id', 'workflow_id', 'error_code', 'started_at', 'heartbeat_at', 'finished_at', 'updated_at']],
]);

it('grants INSERT on no column of audit_logs: appends go through audit_append()', function () {
    $columns = appDb()->select(
        "SELECT column_name, has_column_privilege(current_user, 'audit_logs', column_name, 'INSERT') AS granted
         FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'audit_logs'"
    );

    expect($columns)->toHaveCount(19)
        ->and(array_filter($columns, fn (object $column) => $column->granted))->toBe([]);
});

it('grants the application role nothing on the audit_logs sequence', function (string $privilege) {
    $row = appDb()->selectOne(
        "SELECT has_sequence_privilege(current_user, pg_get_serial_sequence('audit_logs', 'id'), ?) AS granted",
        [$privilege],
    );

    expect($row->granted)->toBeFalse();
})->with(['USAGE', 'SELECT', 'UPDATE']);

it('does not let the application role read the migrations table or call the trigger function', function () {
    expect(fn () => appDb()->select('SELECT * FROM migrations'))
        ->toThrow(QueryException::class, 'permission denied');

    $row = appDb()->selectOne("SELECT has_function_privilege(current_user, 'forbid_mutation()', 'EXECUTE') AS granted");

    expect($row->granted)->toBeFalse();
});

it('does not let the application role run DDL or delete business rows', function (string $statement) {
    $error = dbError(appDb(), fn (Connection $db) => $db->statement($statement));

    expect($error)->not->toBeNull()->and($error->getCode())->toBe('42501');
})->with([
    'create table' => ['CREATE TABLE probe (x int)'],
    'alter table' => ['ALTER TABLE users ADD COLUMN probe int'],
    'drop table' => ['DROP TABLE users'],
    'delete organizations' => ['DELETE FROM organizations'],
    'delete settings' => ['DELETE FROM organization_settings'],
    'delete users' => ['DELETE FROM users'],
    'truncate users' => ['TRUNCATE users'],
]);

it('runs test queries as the application role and DDL as the test owner', function () {
    expect(DB::selectOne('SELECT current_user AS u')->u)->toBe(TestDatabaseGuard::APP_ROLE)
        ->and(ownerDb()->selectOne('SELECT current_user AS u')->u)->toBe(TestDatabaseGuard::OWNER_ROLE);
});

it('keeps the migrate commands from changing the default connection', function () {
    Artisan::call('migrate:status', ['--database' => TestDatabaseGuard::OWNER_CONNECTION]);

    expect(DB::getDefaultConnection())->toBe(TestDatabaseGuard::APP_CONNECTION)
        ->and(DB::selectOne('SELECT current_user AS u')->u)->toBe(TestDatabaseGuard::APP_ROLE);
});

it('gives every role only the expected attributes', function (string $connection) {
    $row = DB::connection($connection)->selectOne(
        'SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
         FROM pg_roles WHERE rolname = current_user'
    );

    expect((array) $row)->toBe([
        'rolsuper' => false, 'rolcreatedb' => false, 'rolcreaterole' => false,
        'rolreplication' => false, 'rolbypassrls' => false,
    ]);
})->with([TestDatabaseGuard::APP_CONNECTION, TestDatabaseGuard::OWNER_CONNECTION]);

it('rejects both test roles on the development and maintenance databases', function (string $connection, string $database) {
    config(['database.connections.elsewhere' => [
        ...config('database.connections.'.$connection),
        'database' => $database,
    ]]);

    expect(fn () => DB::connection('elsewhere')->select('SELECT 1'))
        ->toThrow(QueryException::class, 'permission denied for database');
})->with([TestDatabaseGuard::APP_CONNECTION, TestDatabaseGuard::OWNER_CONNECTION])
    ->with([TestDatabaseGuard::DEVELOPMENT_DATABASE, 'postgres']);

it('keeps the test application role separate from the test owner', function () {
    $row = appDb()->selectOne('SELECT pg_has_role(current_user, ?, ?) AS member', [TestDatabaseGuard::OWNER_ROLE, 'MEMBER']);

    expect($row->member)->toBeFalse();
    expect(fn () => appDb()->statement('SET ROLE '.TestDatabaseGuard::OWNER_ROLE))
        ->toThrow(QueryException::class, 'permission denied');
});

it('leaves the development application role with nothing in the test database', function () {
    $role = TestDatabaseGuard::DEVELOPMENT_APP_ROLE;

    $access = ownerDb()->selectOne(
        "SELECT has_database_privilege(?, current_database(), 'CONNECT') AS connect, has_schema_privilege(?, 'public', 'USAGE') AS usage",
        [$role, $role],
    );
    $grants = ownerDb()->selectOne('SELECT count(*) AS n FROM information_schema.role_table_grants WHERE grantee = ?', [$role]);

    expect($access->connect)->toBeFalse()
        ->and($access->usage)->toBeFalse()
        ->and($grants->n)->toBe(0);
});

it('does not let the test owner create or drop databases and roles', function (string $statement, string $message) {
    expect(fn () => ownerDb()->statement($statement))->toThrow(QueryException::class, $message);
})->with([
    'create database' => ['CREATE DATABASE probe', 'permission denied to create database'],
    'drop development database' => ['DROP DATABASE '.TestDatabaseGuard::DEVELOPMENT_DATABASE, 'must be owner'],
    'drop test database' => ['DROP DATABASE '.TestDatabaseGuard::DATABASE, 'cannot drop the currently open database'],
    'create role' => ['CREATE ROLE probe', 'permission denied to create role'],
    'alter another role' => ['ALTER ROLE '.TestDatabaseGuard::APP_ROLE.' NOLOGIN', 'permission denied to alter role'],
]);
