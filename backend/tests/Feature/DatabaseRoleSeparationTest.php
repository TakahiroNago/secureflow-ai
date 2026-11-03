<?php

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;

/*
| P0-DB-01 / P0-DB-02 (docs/test-strategy.md §12, docs/database-design.md §4)
| The runtime connection (application role) must not be able to run DDL.
| Schema changes are only possible through the dedicated owner (migrator) connection.
*/

it('P0-DB-01: the application role cannot create tables', function () {
    expect(fn () => DB::connection('pgsql')->statement('CREATE TABLE p0_probe_app (x int)'))
        ->toThrow(QueryException::class, 'permission denied');
});

it('P0-DB-01: the runtime connection uses the application role, not the owner', function () {
    $user = DB::connection('pgsql')->selectOne('SELECT current_user AS u')->u;

    expect($user)->toBe(config('database.connections.pgsql.username'))
        ->and($user)->not->toBe(config('database.connections.pgsql_migrator.username'));
});

it('P0-DB-01: the application role is not a superuser', function () {
    $row = DB::connection('pgsql')->selectOne(
        'SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user'
    );

    expect($row->rolsuper)->toBeFalse()
        ->and($row->rolcreatedb)->toBeFalse()
        ->and($row->rolcreaterole)->toBeFalse();
});

it('P0-DB-02: the migrator connection can run DDL', function () {
    // Tests run in the "test" compose service / CI job, which receive the migrator credentials.
    expect(config('database.connections.pgsql_migrator.password'))->not->toBeEmpty();

    $migrator = DB::connection('pgsql_migrator');
    $migrator->statement('CREATE TABLE p0_probe_owner (x int)');
    $migrator->statement('DROP TABLE p0_probe_owner');

    expect($migrator->selectOne('SELECT current_user AS u')->u)
        ->toBe(config('database.connections.pgsql_migrator.username'));
});
