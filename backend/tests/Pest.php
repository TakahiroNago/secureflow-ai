<?php

use App\Models\User;
use App\Support\Database\TestDatabaseGuard;
use Database\Factories\UserFactory;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Tests\Support\SpaClient;
use Tests\TestCase;

/*
| Pest configuration.
| Feature and security tests boot the Laravel application (Tests\TestCase).
*/

pest()->extend(TestCase::class)->in('Feature');
pest()->extend(TestCase::class)->group('security')->in('Security');

/**
 * A browser. Laravel skips the CSRF check while the environment is "testing", so this switches to
 * "local" for the test: the real check has to run. The configuration was already loaded as testing.
 */
function spa(TestCase $test, ?string $origin = 'http://localhost:8080', string $ip = '203.0.113.10'): SpaClient
{
    app()['env'] = 'local';

    return new SpaClient($test, $origin, $ip);
}

function spaLogin(SpaClient $client, string $email, string $password = UserFactory::TEST_PASSWORD): TestResponse
{
    $client->csrf();

    return $client->send('POST', '/api/v1/auth/login', ['email' => $email, 'password' => $password]);
}

function loggedIn(TestCase $test, User $user, string $password = UserFactory::TEST_PASSWORD, string $ip = '203.0.113.10'): SpaClient
{
    $client = spa($test, ip: $ip);
    spaLogin($client, $user->email, $password)->assertOk();

    return $client;
}

/** The application role: what the running application can do. */
function appDb(): Connection
{
    return DB::connection(TestDatabaseGuard::APP_CONNECTION);
}

/** The test owner role: for schema checks and the second defence layer only. */
function ownerDb(): Connection
{
    return DB::connection(TestDatabaseGuard::OWNER_CONNECTION);
}

/**
 * Runs a statement in a savepoint and returns its database error, or null if it succeeded.
 * The savepoint keeps the surrounding test transaction usable after the failure.
 */
function dbError(Connection $db, Closure $statement): ?QueryException
{
    try {
        $db->transaction(fn () => $statement($db));
    } catch (QueryException $exception) {
        return $exception;
    }

    return null;
}

const AUDIT_INSERT_COLUMNS = 'event_id, actor_type, event_type, result, occurred_at, prev_hash, hash';

/**
 * @return list<string>
 */
function auditValues(?string $actorType = 'system', ?string $result = 'success'): array
{
    $hash = str_repeat('0', 64);

    return [(string) Str::uuid7(), $actorType, 'test.event', $result, now()->toIso8601String(), $hash, $hash];
}

function insertAuditLog(Connection $db, ?string $actorType = 'system', ?string $result = 'success'): void
{
    $db->insert(
        'INSERT INTO audit_logs ('.AUDIT_INSERT_COLUMNS.') VALUES (?, ?, ?, ?, ?, ?, ?)',
        auditValues($actorType, $result),
    );
}

function insertOrganization(Connection $db): string
{
    $id = (string) Str::uuid7();
    $db->insert('INSERT INTO organizations (id, name, created_at, updated_at) VALUES (?, ?, now(), now())', [$id, 'Example']);

    return $id;
}

/**
 * @param  array<string, mixed>  $overrides
 */
function insertUser(Connection $db, string $organizationId, array $overrides = []): string
{
    $row = $overrides + [
        'id' => (string) Str::uuid7(),
        'organization_id' => $organizationId,
        'name' => 'Example',
        'email' => Str::uuid7().'@example.com',
        'password' => 'not-a-real-hash',
        'role' => 'member',
        'created_at' => now()->toIso8601String(),
        'updated_at' => now()->toIso8601String(),
    ];

    $db->table('users')->insert($row);

    return (string) $row['id'];
}

/**
 * @param  array<string, mixed>  $overrides
 */
function insertSettings(Connection $db, string $organizationId, array $overrides = []): void
{
    $db->table('organization_settings')->insert($overrides + [
        'organization_id' => $organizationId,
        'monthly_token_limit' => 1000,
        'user_daily_request_limit' => 10,
        'updated_at' => now()->toIso8601String(),
    ]);
}
