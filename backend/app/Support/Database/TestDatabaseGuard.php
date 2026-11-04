<?php

namespace App\Support\Database;

use Illuminate\Support\Facades\DB;
use RuntimeException;

/**
 * Decides whether a schema reset may run (docs/database-design.md §4.6).
 *
 * Every condition must hold and there is deliberately no way to disable a check.
 */
final class TestDatabaseGuard
{
    public const DATABASE = 'secureflow_test';

    public const DEVELOPMENT_DATABASE = 'secureflow';

    public const HOST = 'postgres';

    public const PORT = '5432';

    public const APP_CONNECTION = 'pgsql';

    public const APP_ROLE = 'secureflow_test_app';

    public const DEVELOPMENT_APP_ROLE = 'secureflow_app';

    public const OWNER_CONNECTION = 'pgsql_migrator';

    public const OWNER_ROLE = 'secureflow_test_owner';

    /**
     * @throws RuntimeException when any condition fails
     */
    public static function assertSafe(): void
    {
        $violations = self::configViolations() ?: self::connectionViolations();

        if ($violations !== []) {
            throw new RuntimeException('Test database guard: '.implode('; ', $violations));
        }
    }

    /**
     * @return list<string>
     */
    public static function configViolations(): array
    {
        return self::evaluateConfig(
            app()->environment(),
            (array) config('database.connections.'.self::APP_CONNECTION),
            (array) config('database.connections.'.self::OWNER_CONNECTION),
        );
    }

    /**
     * @param  array<array-key, mixed>  $app
     * @param  array<array-key, mixed>  $owner
     * @return list<string>
     */
    public static function evaluateConfig(string $environment, array $app, array $owner): array
    {
        $violations = $environment === 'testing' ? [] : ['APP_ENV is not testing'];

        foreach ([self::APP_ROLE => $app, self::OWNER_ROLE => $owner] as $role => $connection) {
            $checks = [
                'database' => self::DATABASE,
                'host' => self::HOST,
                'port' => self::PORT,
                'username' => $role,
            ];

            foreach ($checks as $key => $expected) {
                if ((string) ($connection[$key] ?? '') !== $expected) {
                    $violations[] = "{$role} connection has an unexpected {$key}";
                }
            }

            if (($connection['url'] ?? '') !== '' && ($connection['url'] ?? null) !== null) {
                $violations[] = "{$role} connection has DB_URL set";
            }
        }

        return $violations;
    }

    /**
     * Asks the server what it actually connected to. Connection failures propagate (fail closed).
     *
     * @return list<string>
     */
    public static function connectionViolations(): array
    {
        return [
            ...self::evaluateConnection(self::APP_ROLE, self::describe(self::APP_CONNECTION)),
            ...self::evaluateConnection(self::OWNER_ROLE, self::describe(self::OWNER_CONNECTION)),
        ];
    }

    /**
     * @param  array<array-key, mixed>  $server
     * @return list<string>
     */
    public static function evaluateConnection(string $expectedRole, array $server): array
    {
        $violations = [];

        if (($server['database'] ?? null) !== self::DATABASE) {
            $violations[] = "{$expectedRole} is connected to an unexpected database";
        }
        if (($server['role'] ?? null) !== $expectedRole) {
            $violations[] = "{$expectedRole} connection authenticated as an unexpected role";
        }
        if (($server['superuser'] ?? true) !== false) {
            $violations[] = "{$expectedRole} is a superuser";
        }
        if (($server['createdb'] ?? true) !== false) {
            $violations[] = "{$expectedRole} has CREATEDB";
        }
        if (($server['development_connect'] ?? true) !== false) {
            $violations[] = "{$expectedRole} can connect to the development database";
        }

        return $violations;
    }

    /**
     * @return array<string, mixed>
     */
    private static function describe(string $connection): array
    {
        $row = DB::connection($connection)->selectOne(
            'SELECT current_database() AS database, current_user AS role, r.rolsuper AS superuser,
                    r.rolcreatedb AS createdb,
                    COALESCE((SELECT has_database_privilege(current_user, d.oid, \'CONNECT\')
                              FROM pg_database d WHERE d.datname = ?), false) AS development_connect
             FROM pg_roles r WHERE r.rolname = current_user',
            [self::DEVELOPMENT_DATABASE],
        );

        return (array) $row;
    }
}
