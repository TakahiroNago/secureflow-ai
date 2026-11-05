<?php

use App\Support\Database\DatabaseCommandPolicy;
use Illuminate\Contracts\Process\ProcessResult;
use Illuminate\Support\Facades\Process;

/*
| DB-GUARD-02 (docs/test-strategy.md §13, docs/database-design.md §4.5).
| Runs the real commands in a separate process, because the policy is applied while Laravel boots.
| The connection credentials can only reach the test database, so even a policy failure could not
| harm the development database; the survival of the test tables proves the policy held.
*/

function artisanWith(array $environment, string ...$arguments): ProcessResult
{
    return Process::path(base_path())->env($environment)->run(['php', 'artisan', ...$arguments]);
}

// The message is the signal: Laravel exits 0 from a prohibited key:generate and queue:flush.
function wasProhibited(ProcessResult $result): bool
{
    return str_contains($result->output(), 'prohibited from running in this environment');
}

function testTablesExist(): bool
{
    return appDb()->selectOne("SELECT to_regclass('public.users') IS NOT NULL AND to_regclass('public.audit_logs') IS NOT NULL AS present")->present;
}

$schemaResets = [
    'migrate:fresh' => [['migrate:fresh', '--database=pgsql_migrator', '--force']],
    'migrate:refresh' => [['migrate:refresh', '--database=pgsql_migrator', '--force']],
    'migrate:reset' => [['migrate:reset', '--database=pgsql_migrator', '--force']],
    'db:wipe' => [['db:wipe', '--database=pgsql_migrator', '--force']],
];

it('refuses schema resets on anything but the test database', function (array $command, array $environment) {
    expect(wasProhibited(artisanWith($environment, ...$command)))->toBeTrue()
        ->and(testTablesExist())->toBeTrue();
})->with($schemaResets)->with([
    'local, development database' => [['APP_ENV' => 'local', 'DB_DATABASE' => 'secureflow']],
    'local, test database' => [['APP_ENV' => 'local', 'DB_DATABASE' => 'secureflow_test']],
    'production, development database' => [['APP_ENV' => 'production', 'DB_DATABASE' => 'secureflow']],
    'testing env, development database' => [['APP_ENV' => 'testing', 'DB_DATABASE' => 'secureflow']],
    'testing env, similar name' => [['APP_ENV' => 'testing', 'DB_DATABASE' => 'secureflow_test2']],
    'testing env, DB_URL set' => [['APP_ENV' => 'testing', 'DB_DATABASE' => 'secureflow_test', 'DB_URL' => 'pgsql://u:p@db.example.com/secureflow_test']],
    'testing env, other host' => [['APP_ENV' => 'testing', 'DB_DATABASE' => 'secureflow_test', 'DB_HOST' => 'db.example.com']],
    'testing env, other port' => [['APP_ENV' => 'testing', 'DB_DATABASE' => 'secureflow_test', 'DB_PORT' => '5433']],
]);

it('refuses a schema reset aimed at another connection even when the settings are safe', function (string $connection) {
    $result = artisanWith(['APP_ENV' => 'testing', 'DB_DATABASE' => 'secureflow_test'], 'db:wipe', "--database={$connection}", '--force');

    expect($result->failed())->toBeTrue()
        ->and($result->output().$result->errorOutput())->toContain('schema resets must use the test owner connection')
        ->and(testTablesExist())->toBeTrue();
})->with(['pgsql', 'sqlite']);

it('runs the guard on schema resets from the command line', function () {
    $result = artisanWith(
        ['APP_ENV' => 'testing', 'DB_DATABASE' => 'secureflow_test'],
        'db:wipe', '--database=mysql', '--force',
    );

    // Proves the CommandStarting listener fires in the testing environment.
    expect($result->output().$result->errorOutput())->toContain('Test database guard');
});

it('blocks the production-only commands in production equivalents', function (array $command, string $environment) {
    expect(wasProhibited(artisanWith(['APP_ENV' => $environment, 'DB_DATABASE' => 'secureflow'], ...$command)))->toBeTrue()
        ->and(testTablesExist())->toBeTrue();
})->with([
    'migrate:rollback' => [['migrate:rollback', '--database=pgsql_migrator', '--force', '--step=1']],
    'key:generate' => [['key:generate', '--show', '--force']],
    'queue:clear' => [['queue:clear', '--force']],
    'queue:flush' => [['queue:flush']],
    'db:seed' => [['db:seed', '--force']],
    'schema:dump' => [['schema:dump', '--database=pgsql_migrator']],
])->with(['production', 'staging', 'Local', 'unknown']);

it('allows cache:clear in production equivalents', function () {
    $result = artisanWith(['APP_ENV' => 'production', 'CACHE_STORE' => 'array'], 'cache:clear');

    expect($result->successful())->toBeTrue()
        ->and(wasProhibited($result))->toBeFalse();
});

it('allows rollback on the development side through the managed procedure', function () {
    // --pretend: shows the statements without running them, so the schema stays in place.
    $result = artisanWith(
        ['APP_ENV' => 'local', 'DB_DATABASE' => 'secureflow_test'],
        'migrate:rollback', '--database=pgsql_migrator', '--step=1', '--pretend',
    );

    expect($result->successful())->toBeTrue()
        ->and($result->output())->toContain('DROP TABLE audit_chain_heads')
        ->and(testTablesExist())->toBeTrue();
});

it('does not block the other commands in development', function (array $command) {
    expect(wasProhibited(artisanWith(['APP_ENV' => 'local', 'DB_DATABASE' => 'secureflow_test'], ...$command)))->toBeFalse();
})->with([
    'key:generate' => [['key:generate', '--show']],
    'db:seed' => [['db:seed', '--class=DoesNotExist', '--database=pgsql_migrator']],
]);

it('treats only local and testing as non-production', function (string $environment, bool $expected) {
    expect(DatabaseCommandPolicy::isProductionEquivalent($environment))->toBe($expected);
})->with([
    ['local', false],
    ['testing', false],
    ['production', true],
    ['staging', true],
    ['Local', true],
    ['', true],
]);
