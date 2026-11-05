<?php

use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditFailure;
use App\Audit\AuditWriter;
use App\Audit\OutageLog;
use App\Audit\SystemChainLimiter;
use App\Domain\Auth\LoginService;
use App\Models\User;
use App\Support\Database\SingleConnectPostgresConnection;
use App\Support\Database\TcpTimeoutPostgresConnector;
use App\Support\Http\ProblemDetails;
use App\Support\Http\ServiceUnavailableException;
use Database\Factories\UserFactory;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Hashing\HashManager;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Process;
use Illuminate\Testing\TestResponse;
use Ramsey\Uuid\Uuid;
use Symfony\Component\Process\Exception\ProcessSignaledException;
use Tests\Support\FailingAuditWriter;

/*
| What the application records and how it answers when it cannot:
| AUDIT-EVENT-01, AUDIT-FAIL-01, AUDIT-ORACLE-01, AUDIT-AVAIL-01, AUDIT-STATE-01, AUDIT-AUTHERR-01,
| AUDIT-CODE-01, AUDIT-RECOVER-01, AUDIT-SYS-01, AUDIT-SYS-02, AUDIT-SEC-01, AUDIT-LOGAGG-01,
| AUDIT-MON-01, AUDIT-STORAGE-01, AUDIT-WAL-01, AUDIT-REDIS-01. docs/security-design.md §16.5.
*/

uses(DatabaseTransactions::class);

function lastEvent(string $type): ?object
{
    return DB::table('audit_logs')->where('event_type', $type)->orderByDesc('id')->first();
}

/** A body and headers with the per-request parts removed, for comparing two responses. */
function comparable(TestResponse $response): array
{
    $body = $response->json();
    unset($body['trace_id']);

    return [
        $response->getStatusCode(),
        $body,
        $response->headers->get('Content-Type'),
        $response->headers->get('Retry-After'),
    ];
}

function stateOf(): ?array
{
    return app(AuditAvailability::class)->auditState();
}

function isDbFlagged(): bool
{
    return app(AuditAvailability::class)->dbFlagged();
}

// ---- AUDIT-EVENT-01 -----------------------------------------------------------------------------

it('AUDIT-EVENT-01: records a login on the organization chain, by the user', function () {
    $user = User::factory()->create();

    loggedIn($this, $user);

    expect(lastEvent('auth.login'))
        ->organization_id->toBe($user->organization_id)
        ->chain_id->toBe($user->organization_id)
        ->actor_type->toBe('user')
        ->actor_user_id->toBe($user->id)
        ->result->toBe('success')
        ->ip_address->toBe('203.0.113.10');
});

it('AUDIT-EVENT-01: records a wrong password on the organization chain, with no actor', function () {
    $user = User::factory()->create();

    spaLogin(spa($this), $user->email, 'not the password')->assertStatus(401);

    $event = lastEvent('auth.login_failed');

    expect($event)
        ->organization_id->toBe($user->organization_id)
        ->actor_type->toBe('anonymous')
        ->actor_user_id->toBeNull()
        ->resource_type->toBe('user')
        ->resource_id->toBe($user->id)
        ->result->toBe('failure')
        ->and(json_decode($event->metadata, true))->toBe(['reason_code' => 'INVALID_PASSWORD']);
});

it('AUDIT-EVENT-01: gives the reason for each failure', function (string $state, string $reason) {
    $user = User::factory()->{$state}()->create();

    spaLogin(spa($this), $user->email)->assertStatus(401);

    expect(json_decode(lastEvent('auth.login_failed')->metadata, true))->toBe(['reason_code' => $reason]);
})->with([['inactive', 'ACCOUNT_INACTIVE'], ['locked', 'ACCOUNT_LOCKED']]);

it('AUDIT-SYS-01: records an unknown address on the system chain, and not the address', function () {
    $logs = captureLogs();

    spaLogin(spa($this), 'nobody@example.com', 'typed-a-password-here')->assertStatus(401);

    $event = lastEvent('auth.login_failed');
    $row = json_encode($event);
    $logged = implode("\n", array_map(fn (MessageLogged $line) => $line->message.json_encode($line->context), (array) $logs));

    expect($event)
        ->organization_id->toBeNull()
        ->chain_id->toBe('00000000-0000-0000-0000-000000000000')
        ->actor_type->toBe('anonymous')
        ->and(json_decode($event->metadata, true))->toBe(['reason_code' => 'UNKNOWN_ACCOUNT'])
        ->and($row)->not->toContain('nobody')->not->toContain('typed-a-password-here')
        ->and($logged)->not->toContain('nobody')->not->toContain('typed-a-password-here');
});

it('AUDIT-SYS-01: keeps system chain rows out of an organization filter', function () {
    $user = User::factory()->create();

    spaLogin(spa($this), 'nobody@example.com', 'not a password')->assertStatus(401);
    spaLogin(spa($this), $user->email, 'not a password')->assertStatus(401);

    $rows = DB::table('audit_logs')->where('organization_id', $user->organization_id)->get();

    expect($rows)->toHaveCount(1)->and($rows[0]->resource_id)->toBe($user->id);
});

it('AUDIT-EVENT-01: records the lock, as the system acting on the user', function () {
    $user = User::factory()->create();

    foreach (range(1, 5) as $i) {
        spaLogin(spa($this, ip: '198.51.100.'.$i), $user->email, 'wrong password here')->assertStatus(401);
    }

    expect(lastEvent('auth.locked'))
        ->actor_type->toBe('system')
        ->resource_id->toBe($user->id)
        ->severity->toBe('medium');
});

it('AUDIT-EVENT-01: records a logout after the session has ended', function () {
    $user = User::factory()->create();

    loggedIn($this, $user)->send('POST', '/api/v1/auth/logout')->assertNoContent();

    expect(lastEvent('auth.logout'))->actor_user_id->toBe($user->id);
});

it('AUDIT-SEC-01: keeps secrets out of the recorded rows', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);

    $client->send('PATCH', '/api/v1/account/password', ['current_password' => UserFactory::TEST_PASSWORD, 'new_password' => 'a brand new pass phrase'], ['HTTP_IDEMPOTENCY_KEY' => Uuid::uuid7()->toString()])->assertOk();

    $rows = json_encode(DB::table('audit_logs')->get());

    expect($rows)->not->toContain(UserFactory::TEST_PASSWORD)
        ->not->toContain('a brand new pass phrase')
        ->not->toContain('argon2')
        ->and(json_decode(lastEvent('auth.password_changed')->metadata, true))->toBe([]);
});

it('drops metadata keys the event type does not allow', function () {
    $entry = AuditEntry::system(AuditEventType::Login, metadata: ['secret' => 'x']);

    expect($entry->metadata)->toBe([]);
});

// ---- AUDIT-ORACLE-01, AUDIT-FAIL-01 --------------------------------------------------------------

it('AUDIT-ORACLE-01: answers the same 503 for right and wrong credentials when the record fails', function (string $sqlState) {
    $user = User::factory()->create(['email' => 'right@example.com']);
    $inactive = User::factory()->inactive()->create();
    $locked = User::factory()->locked()->create();
    useAuditWriter(new FailingAuditWriter($sqlState));

    $responses = [
        spaLogin(spa($this, ip: '198.51.100.1'), $user->email),
        spaLogin(spa($this, ip: '198.51.100.2'), $user->email, 'not the password'),
        spaLogin(spa($this, ip: '198.51.100.3'), $inactive->email),
        spaLogin(spa($this, ip: '198.51.100.4'), $locked->email),
    ];
    Cache::forget('audit:unavailable');

    foreach ($responses as $response) {
        expect(comparable($response))->toBe(comparable($responses[0]));
    }

    expect($responses[0]->getStatusCode())->toBe(503)
        ->and($responses[0]->json('code'))->toBe('SERVICE_UNAVAILABLE')
        ->and($responses[0]->headers->get('Content-Type'))->toBe('application/problem+json')
        ->and($responses[0]->headers->has('Retry-After'))->toBeTrue();
})->with(['55P03', '57014', '22023', '99999']);

it('AUDIT-ORACLE-01: answers the same 503 for a right and a wrong current password', function (string $sqlState) {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    useAuditWriter(new FailingAuditWriter($sqlState));

    $right = $client->send('PATCH', '/api/v1/account/password', ['current_password' => UserFactory::TEST_PASSWORD, 'new_password' => 'a brand new pass phrase'], ['HTTP_IDEMPOTENCY_KEY' => Uuid::uuid7()->toString()]);
    $wrong = $client->send('PATCH', '/api/v1/account/password', ['current_password' => 'not the password', 'new_password' => 'a brand new pass phrase'], ['HTTP_IDEMPOTENCY_KEY' => Uuid::uuid7()->toString()]);

    expect(comparable($right))->toBe(comparable($wrong))
        ->and($right->getStatusCode())->toBe(503)
        ->and($right->json('detail'))->toBe(ProblemDetails::PASSWORD_CHANGE_UNAVAILABLE_DETAIL);
})->with(['55P03', '57014', '22023']);

it('AUDIT-FAIL-01: a login that cannot be recorded does not happen', function () {
    $user = User::factory()->create(['failed_login_count' => 3]);
    useAuditWriter(new FailingAuditWriter('55P03'));
    $logs = captureLogs();

    $client = spa($this);
    spaLogin($client, $user->email)->assertStatus(503);

    $failed = linesWithMetric($logs, 'audit.write_failed');
    $fresh = $user->fresh();

    expect($fresh->last_login_at)->toBeNull()
        ->and($fresh->failed_login_count)->toBe(3)
        ->and($failed)->toHaveCount(1)
        ->and($failed[0]->context)->toMatchArray(['event_type' => 'auth.login', 'outcome' => 'login_denied', 'failure_class' => 'transient', 'sqlstate' => '55P03']);

    useAuditWriter(new AuditWriter);
    $client->send('GET', '/api/v1/auth/me')->assertStatus(401);
});

it('AUDIT-FAIL-01: a failed attempt keeps counting towards the lock when it cannot be recorded', function () {
    $user = User::factory()->create(['failed_login_count' => 4]);
    useAuditWriter(new FailingAuditWriter('55P03'));

    spaLogin(spa($this), $user->email, 'not the password')->assertStatus(503);

    expect($user->fresh()->isLocked())->toBeTrue();
});

it('AUDIT-FAIL-01: a lock stays in place when it cannot be recorded', function () {
    $user = User::factory()->create(['failed_login_count' => 4]);
    useAuditWriter(new FailingAuditWriter('55P03', only: [AuditEventType::Locked]));
    $logs = captureLogs();

    spaLogin(spa($this), $user->email, 'not the password')->assertStatus(503);

    expect($user->fresh()->isLocked())->toBeTrue()
        ->and(linesWithMetric($logs, 'audit.write_failed')[0]->context)->toMatchArray(['event_type' => 'auth.locked', 'failure_class' => 'transient']);
});

it('AUDIT-FAIL-01: a logout ends the session even when it cannot be recorded', function () {
    $client = loggedIn($this, User::factory()->create());
    useAuditWriter(new FailingAuditWriter('55P03'));
    $logs = captureLogs();

    $client->send('POST', '/api/v1/auth/logout')->assertNoContent();
    $client->send('GET', '/api/v1/auth/me')->assertStatus(401);

    expect(linesWithMetric($logs, 'audit.write_failed')[0]->context['outcome'])->toBe('logout_unrecorded');
});

it('AUDIT-AUTHERR-01: a database failure is not AUTH_FAILED', function () {
    $user = User::factory()->create();

    $client = spa($this);
    $client->csrf();
    config(['database.connections.pgsql.port' => 1]);
    DB::purge('pgsql');

    $response = $client->send('POST', '/api/v1/auth/login', ['email' => $user->email, 'password' => UserFactory::TEST_PASSWORD]);

    config(['database.connections.pgsql.port' => 5432]);
    DB::purge('pgsql');
    DB::connection('pgsql')->beginTransaction();

    $response->assertStatus(503)->assertJsonPath('code', 'SERVICE_UNAVAILABLE')->assertHeader('Retry-After');
    expect($response->getContent())->not->toContain('SQLSTATE')->not->toContain('AUTH_FAILED');
});

it('AUDIT-AUTHERR-01: any other failure is an RFC 9457 500 with nothing inside', function () {
    app()->bind(LoginService::class, fn () => throw new RuntimeException('internal detail'));

    $response = spa($this)->csrf()->send('POST', '/api/v1/auth/login', ['email' => 'a@example.com', 'password' => 'x']);

    $response->assertStatus(500)
        ->assertHeader('Content-Type', 'application/problem+json')
        ->assertJsonPath('code', 'INTERNAL_ERROR');
    expect($response->getContent())->not->toContain('internal detail');
});

// ---- AUDIT-STATE-01, AUDIT-CODE-01 ---------------------------------------------------------------

it('AUDIT-STATE-01: storage and configuration failures make the audit log unavailable at once', function (string $sqlState, string $class, ?string $scope) {
    useAuditWriter(new FailingAuditWriter($sqlState, 'ERROR: could not extend file "base/1/2"'));

    spaLogin(spa($this), User::factory()->create()->email)->assertStatus(503);

    expect(stateOf())->toMatchArray(['failure_class' => $class, 'storage_scope' => $scope])
        ->and(isDbFlagged())->toBeFalse();
})->with([
    ['53100', 'storage', 'db_suspected'],
    ['42501', 'permanent_config', null],
    ['42883', 'permanent_config', null],
    ['42P01', 'permanent_config', null],
    ['25006', 'permanent_config', null],
]);

it('AUDIT-STATE-01: lock waits, timeouts and unclassified errors never change the state, however many in a row', function (string $sqlState, string $class) {
    $user = User::factory()->create();
    useAuditWriter(new FailingAuditWriter($sqlState));
    $logs = captureLogs();

    foreach (range(1, 8) as $i) {
        spaLogin(spa($this, ip: '198.51.100.'.$i), $user->email)->assertStatus(503);
    }

    expect(stateOf())->toBeNull()
        ->and(isDbFlagged())->toBeFalse()
        ->and(linesWithMetric($logs, 'audit.write_failed')[0]->context['failure_class'])->toBe($class);
})->with([
    ['55P03', 'transient'],
    ['57014', 'transient'],
    ['22023', 'unclassified'],
    ['23505', 'unclassified'],
    ['99999', 'unclassified'],
    'SF001 outside the recovery check is no success' => ['SF001', 'unclassified'],
]);

it('AUDIT-CODE-01: a lost connection alone does not stop anything: the probe decides', function (string $sqlState, string $message) {
    useAuditWriter(new FailingAuditWriter($sqlState, $message));

    spaLogin(spa($this), User::factory()->create()->email)->assertStatus(503);

    // The database is really up here, so the probe succeeds whatever the message says.
    expect(isDbFlagged())->toBeFalse()->and(stateOf())->toBeNull();
})->with([
    'pg_terminate_backend' => ['HY000', "FATAL:  terminating connection due to administrator command\nserver closed the connection unexpectedly"],
    'idle timeout' => ['HY000', "FATAL:  terminating connection due to idle-in-transaction timeout\nserver closed the connection unexpectedly"],
    'transaction timeout' => ['HY000', "FATAL:  terminating connection due to transaction timeout\nserver closed the connection unexpectedly"],
    'a passing connection failure' => ['08006', 'connection to server failed'],
    'no message at all' => ['HY000', ''],
]);

it('AUDIT-CODE-01: a failing probe with 08006 makes the database unavailable, whatever the first message said', function (string $firstMessage) {
    useAuditWriter(new FailingAuditWriter('HY000', $firstMessage));
    config(['database.connections.pgsql_audit_read.port' => 1]);
    DB::purge('pgsql_audit_read');

    spaLogin(spa($this), User::factory()->create()->email)->assertStatus(503);

    expect(isDbFlagged())->toBeTrue()->and(stateOf())->toBeNull();
})->with(['server closed the connection unexpectedly', 'a message nobody has seen', '']);

it('AUDIT-CODE-01: does not run the probe for other errors', function (string $sqlState) {
    $writer = new FailingAuditWriter($sqlState);
    useAuditWriter($writer);
    config(['database.connections.pgsql_audit_read.port' => 1]);
    DB::purge('pgsql_audit_read');

    spaLogin(spa($this), User::factory()->create()->email)->assertStatus(503);

    expect(isDbFlagged())->toBeFalse();
})->with(['42601', '57014', '55P03', '22023', '23505', '25P02']);

it('AUDIT-CODE-01: probes at most once per interval', function () {
    useAuditWriter(new FailingAuditWriter('HY000'));

    spaLogin(spa($this), User::factory()->create()->email)->assertStatus(503);

    config(['database.connections.pgsql_audit_read.port' => 1]);
    DB::purge('pgsql_audit_read');

    spaLogin(spa($this, ip: '198.51.100.9'), User::factory()->create()->email)->assertStatus(503);

    expect(isDbFlagged())->toBeFalse();
});

it('AUDIT-CODE-01: reads errorInfo, not getCode(), and tolerates exceptions that are not from PDO', function () {
    $connectFailure = new PDOException('SQLSTATE[08006] [7] connection to server failed: Connection refused');
    $connectFailure->errorInfo = ['08006', 7, 'connection to server at "x", port 1 failed: Connection refused'];

    $query = new QueryException('pgsql', 'SELECT 1', [], $connectFailure);

    expect(AuditFailure::from($query))
        ->sqlState->toBe('08006')
        ->class->toBe('connection')
        ->cause->toBe('connection_refused')
        ->and(AuditFailure::from(new RuntimeException('x')))
        ->sqlState->toBeNull()
        ->class->toBe('unclassified');
});

it('AUDIT-WAL-01: a WAL panic is a candidate cause: it does not count as a disk-full, and the probe decides', function () {
    $panic = 'PANIC:  could not write to file "pg_wal/xlogtemp.103": No space left on device'."\nserver closed the connection unexpectedly";
    $writer = new FailingAuditWriter('HY000', $panic);
    useAuditWriter($writer);
    $logs = captureLogs();

    spaLogin(spa($this), User::factory()->create()->email)->assertStatus(503);

    expect(linesWithMetric($logs, 'audit.write_failed')[0]->context)->toMatchArray(['cause' => 'server_panic', 'failure_class' => 'connection'])
        ->and(stateOf())->toBeNull()
        ->and(isDbFlagged())->toBeFalse();

    File::delete(app(OutageLog::class)->directory().'/probe');
    config(['database.connections.pgsql_audit_read.port' => 1]);
    DB::purge('pgsql_audit_read');

    spaLogin(spa($this, ip: '198.51.100.9'), User::factory()->create()->email)->assertStatus(503);

    expect(isDbFlagged())->toBeTrue()->and(stateOf())->toBeNull();
    $this->getJson('/api/health/live')->assertOk();
});

it('AUDIT-STORAGE-01: treats audit_append 53100 as a suspected database problem and never as audit-only', function () {
    useAuditWriter(new FailingAuditWriter('53100', 'ERROR: could not extend file "pg_tblspc/1/2"'));
    $logs = captureLogs();

    spaLogin(spa($this), User::factory()->create()->email)->assertStatus(503);

    $this->getJson('/api/health/ready')->assertStatus(503)->assertExactJson(['status' => 'unavailable']);
    $this->getJson('/api/health/live')->assertOk();

    expect(stateOf()['storage_scope'])->toBe('db_suspected')
        ->and(linesWithMetric($logs, 'audit.outage_started')[0]->context)->toMatchArray(['storage_scope' => 'db_suspected', 'storage_area' => 'table']);
});

it('AUDIT-STATE-01: an unavailable audit log leaves reads working, and business changes do not commit', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    useAuditWriter(new FailingAuditWriter('42501'));

    spaLogin(spa($this, ip: '198.51.100.9'), $user->email)->assertStatus(503);

    $client->send('GET', '/api/v1/auth/me')->assertOk();
    $this->getJson('/api/health/ready')->assertOk();
    $client->send('PATCH', '/api/v1/account/password', ['current_password' => UserFactory::TEST_PASSWORD, 'new_password' => 'a brand new pass phrase'], ['HTTP_IDEMPOTENCY_KEY' => Uuid::uuid7()->toString()])->assertStatus(503);

    expect(Hash::check(UserFactory::TEST_PASSWORD, $user->fresh()->password))->toBeTrue();
});

// ---- AUDIT-AVAIL-01 ------------------------------------------------------------------------------

it('AUDIT-AVAIL-01: rejects everyone the same way before looking at the account', function () {
    $user = User::factory()->create();
    $locked = User::factory()->locked()->create();
    Cache::put('audit:unavailable', ['outage_id' => 'o', 'failure_class' => 'storage', 'storage_scope' => 'db_suspected', 'started_at' => 0, 'next_check_at' => PHP_INT_MAX], 600);

    $hasher = new class(app('hash')) extends HashManager
    {
        public int $checks = 0;

        public function __construct(private readonly HashManager $real)
        {
            parent::__construct(app());
        }

        public function check($value, $hashedValue, array $options = [])
        {
            $this->checks++;

            return $this->real->check($value, $hashedValue, $options);
        }
    };
    app()->instance('hash', $hasher);
    Hash::clearResolvedInstance('hash');

    $responses = [
        spaLogin(spa($this, ip: '198.51.100.1'), $user->email),
        spaLogin(spa($this, ip: '198.51.100.2'), $user->email, 'not the password'),
        spaLogin(spa($this, ip: '198.51.100.3'), 'nobody@example.com'),
        spaLogin(spa($this, ip: '198.51.100.4'), $locked->email),
    ];

    foreach ($responses as $response) {
        expect(comparable($response))->toBe(comparable($responses[0]));
    }

    expect($responses[0]->getStatusCode())->toBe(503)->and($hasher->checks)->toBe(0);
});

it('AUDIT-AVAIL-01: adds no row and needs no write', function () {
    $before = DB::table('audit_logs')->count();

    app(AuditAvailability::class)->assertAvailable();

    expect(DB::table('audit_logs')->count())->toBe($before);
});

it('AUDIT-AVAIL-01: the DB flag answers 503 without a query until it expires, then checks again', function () {
    Cache::put('audit:db_unavailable', true, 7);

    $client = spa($this)->csrf();
    $response = $client->send('POST', '/api/v1/auth/login', ['email' => 'x@example.com', 'password' => 'x']);

    // Fixed, whatever is left on the flag.
    $response->assertStatus(503)->assertHeader('Retry-After', '30');

    Cache::forget('audit:db_unavailable');
    $client->send('POST', '/api/v1/auth/login', ['email' => 'x@example.com', 'password' => 'x'])->assertStatus(401);
});

it('AUDIT-AVAIL-01: with the flag up a session with a login gets 503 without a query, and everything that needs no database still answers', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    $anonymous = spa($this, ip: '198.51.100.8')->csrf();
    Cache::put('audit:db_unavailable', true, 30);

    $queries = 0;
    DB::listen(function () use (&$queries): void {
        $queries++;
    });

    $client->send('GET', '/api/v1/auth/me')->assertStatus(503)->assertJsonPath('code', 'SERVICE_UNAVAILABLE')->assertHeader('Retry-After', '30');
    $client->send('POST', '/api/v1/auth/logout')->assertStatus(503);
    $client->send('PATCH', '/api/v1/account/password', ['current_password' => 'x', 'new_password' => 'y'], ['HTTP_IDEMPOTENCY_KEY' => Uuid::uuid7()->toString()])
        ->assertStatus(503)->assertJsonPath('detail', ProblemDetails::PASSWORD_CHANGE_UNAVAILABLE_DETAIL);

    $anonymous->send('GET', '/api/v1/auth/me')->assertStatus(401);
    $anonymous->send('GET', '/sanctum/csrf-cookie')->assertNoContent();
    $this->getJson('/api/health/live')->assertOk();

    expect($queries)->toBe(0);

    Cache::forget('audit:db_unavailable');
    $client->send('GET', '/api/v1/auth/me')->assertOk();
});

it('AUDIT-AVAIL-01: a failing query on an authenticated route sets the flag through the probe', function () {
    $client = loggedIn($this, User::factory()->create());
    $availability = app(AuditAvailability::class);
    config(['database.connections.pgsql_audit_read.port' => 1]);
    DB::purge('pgsql_audit_read');

    $pdo = new PDOException('down');
    $pdo->errorInfo = ['08006', 7, 'could not translate host name'];
    report(new QueryException('pgsql', 'SELECT 1', [], $pdo));

    expect($availability->dbFlagged())->toBeTrue();
    $client->send('GET', '/api/v1/auth/me')->assertStatus(503);
});

it('AUDIT-AVAIL-01: after the flag expires one request rechecks, and the others get 503 at once', function () {
    $client = loggedIn($this, User::factory()->create());
    Cache::put('audit:db_suspect', true, 600);
    Cache::put('audit:db_recheck', true, 15);

    $client->send('GET', '/api/v1/auth/me')->assertStatus(503);

    // The holder is gone: this request rechecks, the database answers, and the suspicion ends.
    Cache::forget('audit:db_recheck');
    $client->send('GET', '/api/v1/auth/me')->assertOk();

    expect(Cache::get('audit:db_suspect'))->toBeNull()
        ->and(Cache::get('audit:db_recheck'))->toBeNull();
});

it('AUDIT-AVAIL-01: a recheck that fails sets a new flag and releases the lock', function () {
    $client = loggedIn($this, User::factory()->create());
    Cache::put('audit:db_suspect', true, 600);
    config(['database.connections.pgsql_audit_read.port' => 1]);
    DB::purge('pgsql_audit_read');

    $client->send('GET', '/api/v1/auth/me')->assertStatus(503);

    expect(app(AuditAvailability::class)->dbFlagged())->toBeTrue()
        ->and(Cache::get('audit:db_recheck'))->toBeNull()
        ->and(Cache::get('audit:db_suspect'))->not->toBeNull();
});

it('AUDIT-CODE-01: a connection that was never made is tried once, in a statement and in a transaction', function (Closure $use) {
    $attempts = new ArrayObject(['n' => 0]);
    $connection = new SingleConnectPostgresConnection(function () use ($attempts): never {
        $attempts['n']++;
        $pdo = new PDOException('SQLSTATE[08006] [7] could not translate host name');
        $pdo->errorInfo = ['08006', 7, 'could not translate host name'];

        throw $pdo;
    }, 'x', '', ['driver' => 'pgsql', 'name' => 'x']);
    $connection->setReconnector(function () use ($attempts): void {
        $attempts['n'] += 100;
    });

    expect(fn () => $use($connection))->toThrow(PDOException::class);
    expect($attempts['n'])->toBe(1);
})->with([
    'a statement' => [fn ($connection) => $connection->select('SELECT 1')],
    'a transaction' => [fn ($connection) => $connection->transaction(fn () => null, 1)],
]);

it('AUDIT-CODE-01: the connector does not try a second time', function () {
    $connector = app('db.connector.pgsql');
    $method = new ReflectionMethod($connector, 'tryAgainIfCausedByLostConnection');
    $lost = new PDOException('SQLSTATE[08006] [7] could not translate host name');

    expect(fn () => $method->invoke($connector, $lost, 'pgsql:', 'u', 'p', []))->toThrow(PDOException::class);
});

// ---- AUDIT-RECOVER-01 ----------------------------------------------------------------------------

function setOutage(string $outage = 'outage-1', int $nextCheck = 0): void
{
    Cache::put('audit:unavailable', ['outage_id' => $outage, 'failure_class' => 'storage', 'storage_scope' => 'db_suspected', 'started_at' => 0, 'next_check_at' => $nextCheck], 600);
}

function recoveryEventId(string $outage): string
{
    return Uuid::uuid5(AuditAvailability::RECOVERY_NAMESPACE, $outage)->toString();
}

it('AUDIT-RECOVER-01: stays unavailable until the interval has passed', function () {
    setOutage(nextCheck: PHP_INT_MAX);

    expect(fn () => app(AuditAvailability::class)->assertAvailable())->toThrow(ServiceUnavailableException::class);
    expect(DB::table('audit_logs')->where('event_type', 'audit.availability_checked')->count())->toBe(0);
});

it('AUDIT-RECOVER-01: recovers only through a real append, with one row', function () {
    setOutage();
    $logs = captureLogs();
    app(OutageLog::class)->failure('audit', 'storage');

    app(AuditAvailability::class)->assertAvailable();

    $event = lastEvent('audit.availability_checked');

    expect(stateOf())->toBeNull()
        ->and($event->event_id)->toBe(recoveryEventId('outage-1'))
        ->and(json_decode($event->metadata, true))->toBe(['outage_id' => 'outage-1'])
        ->and(linesWithMetric($logs, 'audit.outage_recovered')[0]->context['recovery_scope'])->toBe('audit_path');
});

it('AUDIT-RECOVER-01: a failing append records nothing, does not recurse, and keeps the state', function () {
    setOutage();
    $writer = new FailingAuditWriter('53100');
    useAuditWriter($writer);
    app()->instance(AuditAvailability::class, new AuditAvailability($writer, app(OutageLog::class)));

    expect(fn () => app(AuditAvailability::class)->assertAvailable())->toThrow(ServiceUnavailableException::class);

    expect(stateOf()['outage_id'])->toBe('outage-1')
        ->and(stateOf()['next_check_at'])->toBeGreaterThan(0)
        ->and($writer->attempted)->toBe(['audit.availability_checked']);
});

it('AUDIT-RECOVER-01: SF001 with the matching row means already recorded', function () {
    appendAudit(['event' => recoveryEventId('outage-1'), 'actor_type' => 'system', 'type' => 'audit.availability_checked', 'result' => 'success', 'metadata' => '{"outage_id":"outage-1"}']);
    $count = DB::table('audit_logs')->where('event_id', recoveryEventId('outage-1'))->count();
    setOutage();

    app(AuditAvailability::class)->assertAvailable();

    expect(stateOf())->toBeNull()
        ->and(DB::table('audit_logs')->where('event_id', recoveryEventId('outage-1'))->count())->toBe($count);
});

it('AUDIT-RECOVER-01: SF001 alone is not trusted: the row is read again', function () {
    setOutage();
    useAuditWriter(new FailingAuditWriter('SF001'));
    app()->instance(AuditAvailability::class, new AuditAvailability(new FailingAuditWriter('SF001'), app(OutageLog::class)));
    $logs = captureLogs();

    expect(fn () => app(AuditAvailability::class)->assertAvailable())->toThrow(ServiceUnavailableException::class);

    expect(stateOf()['outage_id'])->toBe('outage-1')
        ->and(linesWithMetric($logs, 'audit.recovery_check_conflict'))->toHaveCount(1);
});

it('AUDIT-RECOVER-01: 23505 is never taken as recorded', function () {
    appendAudit(['event' => recoveryEventId('outage-1'), 'type' => 'audit.availability_checked', 'metadata' => '{"outage_id":"another"}']);
    setOutage();

    expect(fn () => app(AuditAvailability::class)->assertAvailable())->toThrow(ServiceUnavailableException::class);
    expect(stateOf()['outage_id'])->toBe('outage-1');
});

it('AUDIT-RECOVER-01: runs one check at a time', function () {
    setOutage();
    Cache::put('audit:recovery_check', true, 10);

    expect(fn () => app(AuditAvailability::class)->assertAvailable())->toThrow(ServiceUnavailableException::class);
    expect(DB::table('audit_logs')->where('event_type', 'audit.availability_checked')->count())->toBe(0);
});

it('AUDIT-RECOVER-01: a lost state means a new outage id, not the old one', function () {
    useAuditWriter(new FailingAuditWriter('53100'));
    spaLogin(spa($this), User::factory()->create()->email)->assertStatus(503);
    $first = stateOf()['outage_id'];

    Cache::forget('audit:unavailable');
    spaLogin(spa($this, ip: '198.51.100.9'), User::factory()->create()->email)->assertStatus(503);

    expect(stateOf()['outage_id'])->not->toBe($first);
});

// ---- AUDIT-SYS-02 --------------------------------------------------------------------------------

it('AUDIT-SYS-02: limits login attempts per address, across different email addresses', function () {
    config(['audit.login_ip_limit_per_minute' => 3]);
    $client = spa($this)->csrf();

    foreach (range(1, 3) as $i) {
        $client->send('POST', '/api/v1/auth/login', ['email' => "n{$i}@example.com", 'password' => 'x'])->assertStatus(401);
    }

    $client->send('POST', '/api/v1/auth/login', ['email' => 'n4@example.com', 'password' => 'x'])->assertStatus(429)->assertHeader('Retry-After');
});

it('AUDIT-SYS-02: over the cap the response is unchanged, the excess is logged at once and the total before the chain', function () {
    config(['audit.system_chain_limit_per_minute' => 2]);
    $logs = captureLogs();
    $before = DB::table('audit_logs')->whereNull('organization_id')->count();

    foreach (range(1, 5) as $i) {
        spaLogin(spa($this, ip: '198.51.100.'.$i), "n{$i}@example.com", 'x')->assertStatus(401);
    }

    expect(DB::table('audit_logs')->whereNull('organization_id')->count())->toBe($before + 2)
        ->and(linesWithMetric($logs, 'audit.system_chain.suppressed'))->toHaveCount(1);

    $this->travel(2)->minutes();
    expect(Artisan::call('audit:housekeeping'))->toBe(0);

    $event = lastEvent('audit.events_suppressed');

    expect(json_decode($event->metadata, true)['suppressed_count'])->toBe(3)
        ->and(linesWithMetric($logs, 'audit.system_chain.suppressed_total')[0]->context['suppressed_count'])->toBe(3);

    Artisan::call('audit:housekeeping');

    expect(DB::table('audit_logs')->where('event_type', 'audit.events_suppressed')->count())->toBe(1);
});

it('AUDIT-SYS-02: keeps the count and the log when the chain cannot be written, and records it next time', function () {
    config(['audit.system_chain_limit_per_minute' => 0]);
    $limiter = app(SystemChainLimiter::class);
    $limiter->allow();
    $this->travel(2)->minutes();
    $logs = captureLogs();

    useAuditWriter(new FailingAuditWriter('53100'));
    app()->instance(AuditWriter::class, new FailingAuditWriter('53100'));
    Artisan::call('audit:housekeeping');

    expect(linesWithMetric($logs, 'audit.system_chain.suppressed_total'))->toHaveCount(1)
        ->and(linesWithMetric($logs, 'audit.events_suppressed_write_failed'))->toHaveCount(1)
        ->and(lastEvent('audit.events_suppressed'))->toBeNull()
        ->and($limiter->pending())->not->toBeEmpty();

    useAuditWriter(new AuditWriter);
    Artisan::call('audit:housekeeping');

    expect(lastEvent('audit.events_suppressed'))->not->toBeNull()
        ->and($limiter->pending())->toBeEmpty();
});

it('AUDIT-SYS-02: leaves organization chains out of the cap', function () {
    config(['audit.system_chain_limit_per_minute' => 0]);
    $user = User::factory()->create();

    spaLogin(spa($this), $user->email, 'not the password')->assertStatus(401);

    expect(lastEvent('auth.login_failed'))->not->toBeNull();
});

// ---- AUDIT-MON-01 --------------------------------------------------------------------------------

it('AUDIT-MON-01: the gauge and audit:status follow the state', function () {
    $logs = captureLogs();

    Artisan::call('audit:housekeeping');
    expect(linesWithMetric($logs, 'audit.unavailable')[0]->context['value'])->toBe(0)
        ->and(Artisan::call('audit:status'))->toBe(0);

    setOutage(nextCheck: PHP_INT_MAX);
    Artisan::call('audit:housekeeping');
    expect(linesWithMetric($logs, 'audit.unavailable')[1]->context)->toMatchArray(['value' => 1, 'storage_scope' => 'db_suspected'])
        ->and(Artisan::call('audit:status'))->toBe(1);
});

it('schedules the housekeeping', function () {
    $events = app(Schedule::class)->events();
    $housekeeping = array_values(array_filter($events, fn ($event) => $event->description === 'audit:housekeeping'));

    // A scheduled command's output goes to /dev/null, and with it everything logged to stderr.
    expect($housekeeping)->toHaveCount(1)
        ->and($housekeeping[0]->command)->toBeNull()
        ->and($housekeeping[0]->expression)->toBe('* * * * *');
});

// ---- AUDIT-LOGAGG-01 -----------------------------------------------------------------------------

it('AUDIT-LOGAGG-01: one started, one continuing per interval with a count, one recovered', function () {
    $logs = captureLogs();
    $log = app(OutageLog::class);

    foreach (range(1, 5) as $ignored) {
        $log->failure('redis', 'name_resolution');
    }
    $this->travel(61)->seconds();
    $log->failure('redis', 'name_resolution');
    $log->failure('redis', 'name_resolution');
    $log->recovered('redis');

    expect(linesWithMetric($logs, 'redis.outage_started'))->toHaveCount(1)
        ->and(linesWithMetric($logs, 'redis.outage_continuing'))->toHaveCount(1)
        ->and(linesWithMetric($logs, 'redis.outage_continuing')[0]->context['suppressed_count'])->toBe(4)
        ->and(linesWithMetric($logs, 'redis.outage_recovered'))->toHaveCount(1)
        ->and(linesWithMetric($logs, 'redis.outage_recovered')[0]->context['total_count'])->toBe(7);
});

it('AUDIT-LOGAGG-01: counts are exact one at a time, and from many processes never more than the requests', function () {
    $directory = app(OutageLog::class)->directory();
    $script = 'chdir("'.base_path().'"); require "vendor/autoload.php"; $a = require "bootstrap/app.php";'
        .' $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();'
        .' config(["logging.default" => "stderr", "audit.log_state_directory" => "'.$directory.'"]);'
        .' for ($i = 0; $i < 100; $i++) { app(App\Audit\OutageLog::class)->failure("redis", "read_timeout"); }';

    $results = Process::concurrently(function ($pool) use ($script) {
        foreach (range(1, 6) as $ignored) {
            $pool->path(base_path())->command(['php', '-r', $script]);
        }
    });

    $output = '';
    foreach ($results as $result) {
        expect($result->successful())->toBeTrue();
        $output .= $result->errorOutput().$result->output();
    }

    $state = json_decode((string) file_get_contents($directory.'/redis.json'), true);

    // A log line has the name twice: as its message and in its context.
    expect(substr_count($output, '"metric":"redis.outage_started"'))->toBe(1)
        ->and(substr_count($output, '"metric":"redis.outage_continuing"'))->toBe(0)
        ->and($state['total'])->toBeGreaterThan(0)->toBeLessThanOrEqual(600);
});

it('AUDIT-LOGAGG-01: readiness logs one started however often it is polled, one failure for Redis, and one recovered', function () {
    $logs = captureLogs();
    $settings = config('database.redis');

    useRedisSettings(['database.redis.default.host' => '127.0.0.1', 'database.redis.default.port' => 1, 'database.redis.default.max_retries' => 0, 'database.redis.cache.host' => '127.0.0.1', 'database.redis.cache.port' => 1, 'database.redis.cache.max_retries' => 0]);

    foreach (range(1, 4) as $ignored) {
        $this->getJson('/api/health/ready')->assertStatus(503)->assertExactJson(['status' => 'unavailable']);
    }

    expect(linesWithMetric($logs, 'readiness.redis.outage_started'))->toHaveCount(1)
        ->and(linesWithMetric($logs, 'readiness.storage.outage_started'))->toBeEmpty();

    useRedisSettings(['database.redis' => $settings]);
    $this->getJson('/api/health/ready')->assertOk();

    expect(linesWithMetric($logs, 'readiness.redis.outage_recovered'))->toHaveCount(1)
        ->and(linesWithMetric($logs, 'readiness.redis.outage_recovered')[0]->context['total_count'])->toBe(4);
});

it('AUDIT-LOGAGG-01: a change of cause is logged at once', function () {
    $logs = captureLogs();
    $log = app(OutageLog::class);

    $log->failure('redis', 'name_resolution');
    $log->failure('redis', 'read_timeout');

    expect(linesWithMetric($logs, 'redis.outage_continuing')[0]->context['cause'])->toBe('read_timeout');
});

it('AUDIT-LOGAGG-01: bouncing within an interval gives one started', function () {
    $logs = captureLogs();
    $log = app(OutageLog::class);

    foreach (range(1, 4) as $ignored) {
        $log->failure('redis', 'read_timeout');
        $log->recovered('redis');
    }

    expect(linesWithMetric($logs, 'redis.outage_started'))->toHaveCount(1)
        ->and(linesWithMetric($logs, 'redis.outage_recovered'))->toHaveCount(1);

    $log->failure('redis', 'read_timeout');
    $log->failure('redis', 'name_resolution');

    expect(linesWithMetric($logs, 'redis.outage_continuing')[0]->context['flap_count'])->toBeGreaterThan(0);
});

it('AUDIT-LOGAGG-01: discards a corrupted state and marks it', function () {
    $logs = captureLogs();
    $log = app(OutageLog::class);

    $log->failure('redis', 'read_timeout');
    file_put_contents($log->directory().'/redis.json', '{not json');
    $log->failure('redis', 'read_timeout');

    expect(linesWithMetric($logs, 'redis.outage_started'))->toHaveCount(2)
        ->and(linesWithMetric($logs, 'outage_log.state_reset'))->toHaveCount(1);
});

it('AUDIT-LOGAGG-01: falls back to a per-process limit when the state cannot be written, and keeps the file private', function () {
    $logs = captureLogs();
    $log = app(OutageLog::class);
    $log->failure('audit', 'storage');

    expect(substr(sprintf('%o', fileperms($log->directory().'/audit.json')), -3))->toBe('600')
        ->and(substr(sprintf('%o', fileperms($log->directory())), -3))->toBe('700');

    config(['audit.log_state_directory' => '/proc/not-writable']);
    $log->failure('redis', 'read_timeout');
    $log->failure('redis', 'read_timeout');

    $degraded = array_filter((array) $logs, fn (MessageLogged $line) => ($line->context['aggregation'] ?? null) === 'degraded');

    expect($degraded)->toHaveCount(1);
});

it('AUDIT-LOGAGG-01: a lock left behind by a dead process does not block the next one', function () {
    $logs = captureLogs();
    $log = app(OutageLog::class);
    $log->failure('redis', 'read_timeout');

    $script = '$f = fopen("'.$log->directory().'/redis.lock", "c"); flock($f, LOCK_EX); posix_kill(getmypid(), 9);';

    try {
        Process::run(['php', '-r', $script]);
    } catch (ProcessSignaledException) {
        // That was the point: the process died holding the lock.
    }

    $this->travel(61)->seconds();
    $log->failure('redis', 'read_timeout');

    expect(linesWithMetric($logs, 'redis.outage_continuing'))->toHaveCount(1);
});

// ---- AUDIT-REDIS-01, in-process part --------------------------------------------------------------

function stopRedisSessions(): void
{
    useRedisSettings([
        'session.driver' => 'redis',
        'database.redis.session.host' => '127.0.0.1',
        'database.redis.session.port' => 1,
    ]);
    app('session')->forgetDrivers();
}

it('AUDIT-REDIS-01: answers an RFC 9457 503 and does not run authentication when sessions are unavailable', function () {
    $user = User::factory()->create();
    $client = spa($this);
    stopRedisSessions();
    $logs = captureLogs();

    $responses = [
        $client->send('POST', '/api/v1/auth/login', ['email' => $user->email, 'password' => UserFactory::TEST_PASSWORD]),
        $client->send('POST', '/api/v1/auth/login', ['email' => $user->email, 'password' => 'not the password']),
        $client->send('POST', '/api/v1/auth/login', ['email' => 'nobody@example.com', 'password' => 'x']),
    ];

    foreach ($responses as $response) {
        expect(comparable($response))->toBe(comparable($responses[0]));
    }

    $responses[0]->assertStatus(503)->assertHeader('Retry-After')->assertHeader('Content-Type', 'application/problem+json')->assertJsonPath('code', 'SERVICE_UNAVAILABLE');

    $user->refresh();

    expect($user->failed_login_count)->toBe(0)
        ->and(DB::table('audit_logs')->count())->toBe(0)
        ->and(linesWithMetric($logs, 'redis.outage_started'))->toHaveCount(1)
        ->and(linesWithMetric($logs, 'redis.outage_started')[0]->context['cause'])->toBe('connection_refused');
});

it('AUDIT-REDIS-01: covers a login without an Origin, without changing the answer when Redis works', function () {
    $normal = spa($this, origin: null)->send('POST', '/api/v1/auth/login', ['email' => 'a@example.com', 'password' => 'x']);

    stopRedisSessions();

    $down = spa($this, origin: null)->send('POST', '/api/v1/auth/login', ['email' => 'a@example.com', 'password' => 'x']);

    expect($normal->getStatusCode())->toBeIn([401, 419]);
    expect($down->getStatusCode())->toBeIn([$normal->getStatusCode(), 503]);
});

it('AUDIT-REDIS-01: leaves liveness up and readiness down', function () {
    stopRedisSessions();
    useRedisSettings(['database.redis.default.port' => 1, 'database.redis.default.host' => '127.0.0.1', 'database.redis.default.max_retries' => 0]);

    $this->getJson('/api/health/live', ['Referer' => 'http://localhost:8080/', 'Origin' => 'http://localhost:8080'])->assertOk();
    $this->getJson('/api/health/ready')->assertStatus(503)->assertExactJson(['status' => 'unavailable']);
});

it('AUDIT-REDIS-01: gives the password endpoint its own guidance on a 503', function () {
    $client = spa($this);
    stopRedisSessions();

    $client->send('PATCH', '/api/v1/account/password', ['current_password' => 'x', 'new_password' => 'y'])
        ->assertStatus(503)
        ->assertJsonPath('detail', ProblemDetails::PASSWORD_CHANGE_UNAVAILABLE_DETAIL);
});

it('uses a connection with short timeouts for sessions', function () {
    expect(config('session.connection'))->toBe('session')
        ->and(config('database.redis.session.max_retries'))->toBe(0)
        ->and((float) config('database.redis.session.timeout'))->toBeLessThanOrEqual(1.0);
});

it('AUDIT-DBTO-01: configures the timeouts on the application connection, and keeps lock below statement', function () {
    $config = config('database.connections.pgsql');
    $row = appDb()->selectOne("SELECT current_setting('statement_timeout') AS s, current_setting('lock_timeout') AS l, current_setting('idle_in_transaction_session_timeout') AS i");

    expect($row->s)->toBe('5s')->and($row->l)->toBe('3s')->and($row->i)->toBe('30s')
        ->and((int) $config['server_options']['lock_timeout'])->toBeLessThan((int) $config['server_options']['statement_timeout'])
        ->and($config['keepalives'])->toBe(1)
        ->and($config['tcp_user_timeout'])->toBeGreaterThan(0)
        ->and(app('db.connector.pgsql'))->toBeInstanceOf(TcpTimeoutPostgresConnector::class);
});

it('AUDIT-DBTO-01: applies the settings to the role connection only, not the migration owner', function () {
    expect(config('database.connections.pgsql_migrator.server_options'))->toBeNull();
});
