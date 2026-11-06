<?php

use App\Audit\AuditLogger;
use App\Audit\AuditWriter;
use App\Domain\Auth\PendingFingerprintStore;
use App\Domain\Auth\RetiredSessions;
use App\Models\User;
use App\Models\Workflow;
use App\Support\Database\TestDatabaseGuard;
use App\Support\Organization\OrganizationContext;
use Database\Factories\UserFactory;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Tests\Support\ArrayPendingFingerprintStore;
use Tests\Support\ArrayRetiredSessions;
use Tests\Support\SpaClient;
use Tests\TestCase;

/*
| Pest configuration.
| Feature and security tests boot the Laravel application (Tests\TestCase).
*/

pest()->extend(TestCase::class)->in('Feature');
pest()->extend(TestCase::class)->group('security')->in('Security');
pest()->extend(TestCase::class)->group('isolation')->in('Isolation');
pest()->extend(TestCase::class)->group('concurrency')->in('Concurrency');

/** A workflow created by this user, in this user's organization. */
function workflowOf(User $creator, array $attributes = []): Workflow
{
    return app(OrganizationContext::class)->run(
        $creator->organization_id,
        fn () => Workflow::factory()->create(['created_by' => $creator->id, ...$attributes]),
    );
}

/** Read back, as a logged-in user would be: the factory does not know the database defaults. */
function userIn(string $organizationId, string $role = 'member', array $attributes = []): User
{
    return User::factory()->create(['organization_id' => $organizationId, 'role' => $role, ...$attributes])->refresh();
}

/**
 * @param  array<string, mixed>  $overrides
 */
function insertRevision(Connection $db, Workflow $workflow, array $overrides = []): string
{
    $row = $overrides + [
        'id' => (string) Str::uuid7(),
        'organization_id' => $workflow->organization_id,
        'workflow_id' => $workflow->id,
        'revision_no' => 1,
        'plan_snapshot' => '{}',
        'plan_hash' => str_repeat('a', 64),
        'hash_version' => 1,
        'policy_version' => '2026.11.1',
        'change_type' => 'ai_generated',
        'created_at' => now()->toIso8601String(),
    ];
    $db->table('workflow_revisions')->insert($row);

    return (string) $row['id'];
}

/**
 * @param  array<string, mixed>  $overrides
 */
function insertTask(Connection $db, Workflow $workflow, array $overrides = []): string
{
    $row = $overrides + [
        'id' => (string) Str::uuid7(),
        'organization_id' => $workflow->organization_id,
        'workflow_id' => $workflow->id,
        'position' => 1,
        'title' => 'Title',
        'description' => 'Description',
        'action_type' => 'text.analyze',
        'steps' => '[]',
        'priority' => 'low',
        'target_data' => 'Target',
        'impact_summary' => 'Impact',
        'derived_permissions' => '["ai.text.read"]',
        'ai_claimed_permissions' => '[]',
        'policy_decision' => 'allowed',
        'created_at' => now()->toIso8601String(),
        'updated_at' => now()->toIso8601String(),
    ];
    $db->table('workflow_tasks')->insert($row);

    return (string) $row['id'];
}

/**
 * @param  array<string, mixed>  $overrides
 */
function insertApproval(Connection $db, Workflow $workflow, string $revisionId, string $decidedBy, array $overrides = []): string
{
    $row = $overrides + [
        'id' => (string) Str::uuid7(),
        'organization_id' => $workflow->organization_id,
        'workflow_id' => $workflow->id,
        'workflow_revision_id' => $revisionId,
        'plan_hash' => str_repeat('a', 64),
        'decision' => 'approved',
        'decided_by' => $decidedBy,
        'acknowledged_risks' => true,
        'created_at' => now()->toIso8601String(),
    ];
    $db->table('approvals')->insert($row);

    return (string) $row['id'];
}

/**
 * @param  array<string, mixed>  $overrides
 */
function insertExecution(Connection $db, Workflow $workflow, string $revisionId, string $approvalId, array $overrides = []): string
{
    $row = $overrides + [
        'id' => (string) Str::uuid7(),
        'organization_id' => $workflow->organization_id,
        'workflow_id' => $workflow->id,
        'approval_id' => $approvalId,
        'workflow_revision_id' => $revisionId,
        'idempotency_key' => (string) Str::uuid7(),
        'requested_by' => $workflow->created_by,
        'status' => 'queued',
        'created_at' => now()->toIso8601String(),
        'updated_at' => now()->toIso8601String(),
    ];
    $db->table('workflow_executions')->insert($row);

    return (string) $row['id'];
}

/** Empties the workflow tables. Test database only: the owner switches the triggers off. */
function resetWorkflowTables(): void
{
    $db = ownerDb();
    $db->statement('ALTER TABLE workflow_revisions DISABLE TRIGGER USER');
    $db->statement('ALTER TABLE approvals DISABLE TRIGGER USER');
    $db->statement('TRUNCATE workflow_executions, approvals, workflow_tasks, workflow_revisions, workflows');
    $db->statement('ALTER TABLE workflow_revisions ENABLE TRIGGER USER');
    $db->statement('ALTER TABLE approvals ENABLE TRIGGER USER');
}

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

const AUDIT_INSERT_COLUMNS = 'event_id, actor_type, event_type, result, occurred_at, prev_hash, hash, chain_seq, hash_version';

const AUDIT_INSERT_PLACEHOLDERS = '?, ?, ?, ?, ?, ?, ?, ?, ?';

/**
 * @return list<string|int|null>
 */
function auditValues(?string $actorType = 'system', ?string $result = 'success'): array
{
    $hash = str_repeat('0', 64);

    return [(string) Str::uuid7(), $actorType, 'test.event', $result, now()->toIso8601String(), $hash, $hash, random_int(1, PHP_INT_MAX), 1];
}

/** A direct insert: only the owner can do this, which is what the constraint tests need. */
function insertAuditLog(Connection $db, ?string $actorType = 'system', ?string $result = 'success'): void
{
    $db->insert(
        'INSERT INTO audit_logs ('.AUDIT_INSERT_COLUMNS.') VALUES ('.AUDIT_INSERT_PLACEHOLDERS.')',
        auditValues($actorType, $result),
    );
}

/**
 * audit_append() as the application role, with valid arguments unless overridden.
 *
 * @param  array<string, mixed>  $overrides
 */
function appendAudit(array $overrides = [], ?Connection $db = null): int
{
    $arguments = $overrides + [
        'event' => (string) Str::uuid7(),
        'organization' => null,
        'actor_type' => 'system',
        'actor' => null,
        'type' => 'test.event',
        'resource_type' => null,
        'resource' => null,
        'result' => 'success',
        'severity' => null,
        'ip' => null,
        'request' => null,
        'metadata' => '{}',
    ];

    $order = ['event', 'organization', 'actor_type', 'actor', 'type', 'resource_type', 'resource', 'result', 'severity', 'ip', 'request', 'metadata'];

    return (int) ($db ?? appDb())->selectOne(
        'SELECT public.audit_append(?::uuid, ?::uuid, ?, ?::uuid, ?, ?, ?::uuid, ?, ?, ?::inet, ?::uuid, ?::jsonb) AS seq',
        array_map(fn (string $name) => $arguments[$name], $order),
    )->seq;
}

/** errorInfo[0], the way the application reads it. */
function sqlStateFrom(?Throwable $exception): ?string
{
    return $exception?->getPrevious()->errorInfo[0] ?? null;
}

/** Empties the append-only tables. Test database only: the owner switches the triggers off. */
function resetAuditTables(): void
{
    $db = ownerDb();
    $db->statement('ALTER TABLE audit_logs DISABLE TRIGGER USER');
    $db->statement('ALTER TABLE audit_chain_heads DISABLE TRIGGER USER');
    $db->statement('TRUNCATE audit_logs, audit_chain_heads');
    $db->statement('ALTER TABLE audit_logs ENABLE TRIGGER USER');
    $db->statement('ALTER TABLE audit_chain_heads ENABLE TRIGGER USER');
}

function useAuditWriter(AuditWriter $writer): void
{
    app()->instance(AuditWriter::class, $writer);
    app()->forgetInstance(AuditLogger::class);

    // A route keeps its controller, and through it the old writer, for the rest of the test.
    foreach (app('router')->getRoutes() as $route) {
        $route->controller = null;
    }
}

/** The manager copies the Redis settings when it is built, so a change needs a new manager. */
function useRedisSettings(array $settings): void
{
    config($settings);
    app()->forgetInstance('redis');
    Redis::clearResolvedInstance('redis');
}

function retiredSessions(): ArrayRetiredSessions
{
    $sessions = app(RetiredSessions::class);
    assert($sessions instanceof ArrayRetiredSessions);

    return $sessions;
}

function pendingStore(): ArrayPendingFingerprintStore
{
    $store = app(PendingFingerprintStore::class);
    assert($store instanceof ArrayPendingFingerprintStore);

    return $store;
}

/**
 * Every log line from now on, with its context.
 *
 * @return ArrayObject<int, MessageLogged>
 */
function captureLogs(): ArrayObject
{
    $lines = new ArrayObject;
    Event::listen(MessageLogged::class, function (MessageLogged $line) use ($lines): void {
        $lines[] = $line;
    });

    return $lines;
}

/**
 * @param  ArrayObject<int, MessageLogged>  $lines
 * @return list<MessageLogged>
 */
function linesWithMetric(ArrayObject $lines, string $metric): array
{
    return array_values(array_filter((array) $lines, fn (MessageLogged $line) => ($line->context['metric'] ?? null) === $metric));
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
