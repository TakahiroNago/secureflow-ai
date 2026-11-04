<?php

use App\Support\Database\TestDatabaseGuard;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;

/*
| DB-GUARD-01 (docs/test-strategy.md §13, docs/database-design.md §4.6).
*/

function safeConfig(string $role): array
{
    return ['database' => 'secureflow_test', 'host' => 'postgres', 'port' => '5432', 'username' => $role, 'url' => null];
}

function safeServer(string $role): array
{
    return ['database' => 'secureflow_test', 'role' => $role, 'superuser' => false, 'createdb' => false, 'development_connect' => false];
}

it('passes in the real test environment', function () {
    expect(TestDatabaseGuard::configViolations())->toBe([])
        ->and(TestDatabaseGuard::connectionViolations())->toBe([]);

    TestDatabaseGuard::assertSafe();
});

it('accepts a safe configuration', function () {
    expect(TestDatabaseGuard::evaluateConfig('testing', safeConfig('secureflow_app'), safeConfig('secureflow_test_owner')))->toBe([]);
});

it('rejects an environment other than exactly testing', function (string $environment) {
    expect(TestDatabaseGuard::evaluateConfig($environment, safeConfig('secureflow_app'), safeConfig('secureflow_test_owner')))
        ->toContain('APP_ENV is not testing');
})->with(['local', 'production', 'staging', 'Testing', 'testing ', '']);

it('rejects any unsafe setting on either connection', function (string $key, mixed $value) {
    $unsafe = fn (string $role) => [...safeConfig($role), $key => $value];

    expect(TestDatabaseGuard::evaluateConfig('testing', $unsafe('secureflow_app'), safeConfig('secureflow_test_owner')))->not->toBe([])
        ->and(TestDatabaseGuard::evaluateConfig('testing', safeConfig('secureflow_app'), $unsafe('secureflow_test_owner')))->not->toBe([]);
})->with([
    'development database' => ['database', 'secureflow'],
    'similar name, prefix' => ['database', 'secureflow_test2'],
    'similar name, suffix' => ['database', 'my_secureflow_test'],
    'different case' => ['database', 'SECUREFLOW_TEST'],
    'empty database' => ['database', ''],
    'other host' => ['host', 'db.example.com'],
    'loopback host' => ['host', '127.0.0.1'],
    'other port' => ['port', '5433'],
    'other user' => ['username', 'postgres'],
    'DB_URL set' => ['url', 'pgsql://u:p@db.example.com/secureflow'],
]);

it('rejects swapped roles', function () {
    expect(TestDatabaseGuard::evaluateConfig('testing', safeConfig('secureflow_test_owner'), safeConfig('secureflow_app')))->not->toBe([]);
});

it('rejects the development owner as the schema owner', function () {
    expect(TestDatabaseGuard::evaluateConfig('testing', safeConfig('secureflow_app'), safeConfig('secureflow_owner')))->not->toBe([]);
});

it('accepts what a safe server reports', function (string $role) {
    expect(TestDatabaseGuard::evaluateConnection($role, safeServer($role)))->toBe([]);
})->with(['secureflow_app', 'secureflow_test_owner']);

it('rejects what an unsafe server reports', function (string $key, mixed $value, string $message) {
    $server = [...safeServer('secureflow_test_owner'), $key => $value];

    expect(implode(' ', TestDatabaseGuard::evaluateConnection('secureflow_test_owner', $server)))->toContain($message);
})->with([
    'other database' => ['database', 'secureflow', 'unexpected database'],
    'other role' => ['role', 'secureflow_owner', 'unexpected role'],
    'superuser' => ['superuser', true, 'superuser'],
    'createdb' => ['createdb', true, 'CREATEDB'],
    'owner reaches development' => ['development_connect', true, 'development database'],
]);

it('treats a missing answer from the server as unsafe', function () {
    expect(TestDatabaseGuard::evaluateConnection('secureflow_test_owner', []))->toHaveCount(5);
});

it('fails closed when the owner cannot reach the configured database', function () {
    config(['database.connections.pgsql_migrator.database' => 'secureflow']);
    DB::purge('pgsql_migrator');

    expect(fn () => TestDatabaseGuard::connectionViolations())
        ->toThrow(QueryException::class, 'permission denied for database');
});

it('detects a connection that authenticates as the wrong role', function () {
    config(['database.connections.pgsql' => config('database.connections.pgsql_migrator')]);
    DB::purge('pgsql');

    expect(implode(' ', TestDatabaseGuard::connectionViolations()))->toContain('unexpected role');
});

it('refuses through assertSafe when the settings are unsafe', function () {
    config(['database.connections.pgsql.database' => 'secureflow']);

    expect(fn () => TestDatabaseGuard::assertSafe())
        ->toThrow(RuntimeException::class, 'Test database guard');
});
