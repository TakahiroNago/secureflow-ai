<?php

use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Audit\OutageLog;
use App\Domain\Auth\AuthenticatedSession;
use App\Domain\Auth\LoginService;
use App\Domain\Auth\PasswordChangeResult;
use App\Domain\Auth\PasswordChangeService;
use App\Models\User;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ProblemDetails;
use App\Support\Http\ServiceUnavailableException;
use Database\Factories\UserFactory;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Testing\TestResponse;
use Ramsey\Uuid\Uuid;
use Tests\Support\FailingAuditWriter;
use Tests\Support\SpaClient;
use Tests\Support\ThrowingRollbackPdo;

/*
| Real commits, real errors and more than one connection: what a test transaction cannot show
| (docs/test-strategy.md §15). AUDIT-FAIL-01, AUDIT-TX-01 and the concurrency cases of AUDIT-PWCHG-01.
*/

const CHANGED_PASSWORD = 'a brand new pass phrase';

beforeEach(function () {
    resetAuditTables();
    $this->organization = insertOrganization(appDb());
    $this->user = User::factory()->create(['organization_id' => $this->organization]);
});

afterEach(function () {
    if (ownerDb()->transactionLevel() > 0) {
        ownerDb()->rollBack();
    }

    resetAuditTables();
    ownerDb()->table('users')->where('organization_id', $this->organization)->delete();
    ownerDb()->table('organizations')->where('id', $this->organization)->delete();
});

function changeTo(SpaClient $client, string $key, string $new = CHANGED_PASSWORD): TestResponse
{
    return $client->send('PATCH', '/api/v1/account/password', ['current_password' => UserFactory::TEST_PASSWORD, 'new_password' => $new], ['HTTP_IDEMPOTENCY_KEY' => $key]);
}

function lockHeadOf(string $chain): void
{
    ownerDb()->beginTransaction();
    ownerDb()->select('SELECT * FROM audit_chain_heads WHERE chain_id = ? FOR UPDATE', [$chain]);
}

function eventsOf(string $type): int
{
    return appDb()->table('audit_logs')->where('event_type', $type)->count();
}

/** The same derivation as the service: a test that repeats it fails when either side changes. */
function committedKeyHash(User $user, string $key): string
{
    $secret = hash_hkdf('sha256', config()->string('app.key'), 32, 'password-change-idempotency');

    return hash_hmac('sha256', 'password-change-idempotency|'.$user->id.'|'.$key, $secret);
}

// ---- AUDIT-FAIL-01: an actual 55P03 --------------------------------------------------------------

it('AUDIT-FAIL-01: a head locked elsewhere gives a real 55P03: 503, no session, nothing changed', function () {
    appendAudit(['organization' => $this->organization]);
    $logs = captureLogs();
    $client = spa($this);
    $client->csrf();

    lockHeadOf($this->organization);
    $response = $client->send('POST', '/api/v1/auth/login', ['email' => $this->user->email, 'password' => UserFactory::TEST_PASSWORD]);
    ownerDb()->rollBack();

    $response->assertStatus(503)->assertJsonPath('code', 'SERVICE_UNAVAILABLE');
    $client->send('GET', '/api/v1/auth/me')->assertStatus(401);

    expect($this->user->fresh()->last_login_at)->toBeNull()
        ->and(eventsOf('auth.login'))->toBe(0)
        ->and(linesWithMetric($logs, 'audit.write_failed')[0]->context)->toMatchArray(['sqlstate' => '55P03', 'failure_class' => 'transient', 'outcome' => 'login_denied'])
        ->and(app(AuditAvailability::class)->auditState())->toBeNull();

    spaLogin(spa($this), $this->user->email)->assertOk();
    expect(eventsOf('auth.login'))->toBe(1);
});

it('AUDIT-FAIL-01: a failed login keeps its count when the head is locked elsewhere', function () {
    appendAudit(['organization' => $this->organization]);
    $client = spa($this);
    $client->csrf();

    lockHeadOf($this->organization);
    $response = $client->send('POST', '/api/v1/auth/login', ['email' => $this->user->email, 'password' => 'not the password']);
    ownerDb()->rollBack();

    $response->assertStatus(503);

    expect($this->user->fresh()->failed_login_count)->toBe(1)
        ->and(eventsOf('auth.login_failed'))->toBe(0);
});

it('AUDIT-CONC-01: the system chain being locked does not hold up an organization chain', function () {
    appendAudit();
    lockHeadOf('00000000-0000-0000-0000-000000000000');

    $start = hrtime(true);
    spaLogin(spa($this), $this->user->email)->assertOk();
    $seconds = (hrtime(true) - $start) / 1e9;

    expect($seconds)->toBeLessThan(1.5);
});

// ---- AUDIT-TX-01 ---------------------------------------------------------------------------------

it('AUDIT-TX-01: a lost connection does not run audit_append() a second time', function () {
    $writer = new FailingAuditWriter('HY000', 'server closed the connection unexpectedly');
    useAuditWriter($writer);

    expect(app(AuditLogger::class)->recordAfterTransaction(AuditEntry::system(AuditEventType::Locked), 'x'))->toBeFalse()
        ->and($writer->attempted)->toBe(['auth.locked']);
});

// ---- AUDIT-PWCHG-01: locks and races -------------------------------------------------------------

it('a row lock held too long fails the change with 503, and the same key works afterwards', function () {
    $client = loggedIn($this, $this->user);
    $key = (string) Uuid::uuid7();

    ownerDb()->beginTransaction();
    ownerDb()->select('SELECT 1 FROM users WHERE id = ? FOR UPDATE', [$this->user->id]);
    $response = changeTo($client, $key);
    ownerDb()->rollBack();

    $response->assertStatus(503)->assertJsonPath('detail', ProblemDetails::PASSWORD_CHANGE_UNAVAILABLE_DETAIL);

    expect(Hash::check(UserFactory::TEST_PASSWORD, $this->user->fresh()->password))->toBeTrue()
        ->and(pendingStore()->values)->toBe([]);

    changeTo($client, $key)->assertOk();

    expect(eventsOf('auth.password_changed'))->toBe(1);
});

it('a request that loses the race to another key writes no fingerprint and changes nothing', function () {
    $client = loggedIn($this, $this->user);
    $winner = Hash::make('the other request won');
    $user = $this->user;

    pendingStore()->beforePrepare = fn () => ownerDb()->table('users')->where('id', $user->id)->update([
        'password' => $winner, 'password_changed_at' => now(),
    ]);

    changeTo($client, (string) Uuid::uuid7())->assertStatus(422)->assertJsonPath('code', 'CURRENT_PASSWORD_INVALID');

    expect(pendingStore()->values)->toBe([])
        ->and($user->fresh()->password)->toBe($winner)
        ->and(eventsOf('auth.password_changed'))->toBe(0);
});

it('AUDIT-SESSION-01: an older session that loses the race with the same key and content ends, and gets 401', function () {
    $client = loggedIn($this, $this->user);
    $key = (string) Uuid::uuid7();
    $winner = Hash::make(CHANGED_PASSWORD);
    $user = $this->user;
    $previous = $user->password;

    pendingStore()->beforePrepare = fn () => ownerDb()->table('users')->where('id', $user->id)->update([
        'password' => $winner, 'password_changed_at' => now(),
        'password_change_key_hash' => committedKeyHash($user, $key), 'password_change_previous_hash' => $previous,
    ]);

    changeTo($client, $key)->assertStatus(401);
    pendingStore()->beforePrepare = null;

    $client->send('GET', '/api/v1/auth/me')->assertStatus(401);

    expect($user->fresh()->password)->toBe($winner);
});

it('AUDIT-SESSION-01: the same session that made the change gets 200 from its fingerprint', function () {
    $client = loggedIn($this, $this->user);
    $key = (string) Uuid::uuid7();
    $winner = Hash::make(CHANGED_PASSWORD);
    $user = $this->user;
    $previous = $user->password;

    // The first of two parallel requests of one session: it has written this session's fingerprint.
    pendingStore()->beforePrepare = function () use ($user, $winner, $previous, $key) {
        pendingStore()->values[app('session')->driver()->getId()] = app(AuthenticatedSession::class)->pendingFingerprint($winner);

        ownerDb()->table('users')->where('id', $user->id)->update([
            'password' => $winner, 'password_changed_at' => now(),
            'password_change_key_hash' => committedKeyHash($user, $key), 'password_change_previous_hash' => $previous,
        ]);
    };

    changeTo($client, $key)->assertOk();
    pendingStore()->beforePrepare = null;

    $client->send('GET', '/api/v1/auth/me')->assertOk();
});

function raceAsSameSession(User $user, string $key, string $winner, string $previous, Closure $then): void
{
    pendingStore()->beforePrepare = function () use ($user, $winner, $previous, $key, $then) {
        $sessionId = app('session')->driver()->getId();
        pendingStore()->values[$sessionId] = app(AuthenticatedSession::class)->pendingFingerprint($winner);
        $then($sessionId);

        ownerDb()->table('users')->where('id', $user->id)->update([
            'password' => $winner, 'password_changed_at' => now(),
            'password_change_key_hash' => committedKeyHash($user, $key), 'password_change_previous_hash' => $previous,
        ]);
    };
}

it('AUDIT-SESSION-01: a request of the same session that finds it already rotated gets 401, with no session or cookie', function () {
    $client = loggedIn($this, $this->user);
    $cookie = $client->sessionCookie();
    $retiredBefore = count(retiredSessions()->ids);
    $key = (string) Uuid::uuid7();

    raceAsSameSession($this->user, $key, Hash::make(CHANGED_PASSWORD), $this->user->password, function (string $sessionId) {
        retiredSessions()->ids[$sessionId] = true;
    });

    $response = changeTo($client, $key)->assertStatus(401);
    pendingStore()->beforePrepare = null;

    expect(array_map(fn ($c) => $c->getName(), $response->baseResponse->headers->getCookies()))->not->toContain(config('session.cookie'))
        ->and($client->sessionCookie())->toBe($cookie)
        ->and(retiredSessions()->ids)->toHaveCount($retiredBefore + 1);
});

it('AUDIT-SESSION-01: the request that committed goes first: another one gets 401 until its time has passed', function () {
    $client = loggedIn($this, $this->user);
    $retiredBefore = retiredSessions()->ids;
    $key = (string) Uuid::uuid7();

    raceAsSameSession($this->user, $key, Hash::make(CHANGED_PASSWORD), $this->user->password, function (string $sessionId) {
        pendingStore()->owners[$sessionId] = ['owner' => 'the committing request', 'until' => now()->getTimestamp() + 15];
    });

    changeTo($client, $key)->assertStatus(401);
    pendingStore()->beforePrepare = null;

    expect(retiredSessions()->ids)->toBe($retiredBefore);

    // That request died before rotating. The session is not stuck.
    $this->travel(16)->seconds();

    $client->send('GET', '/api/v1/auth/me')->assertOk();

    expect(retiredSessions()->ids)->toHaveCount(count($retiredBefore) + 1);
});

it('after a lost race the row decides, by key alone: a matching row is a replay', function () {
    $key = (string) Uuid::uuid7();
    $user = $this->user;
    $service = app(PasswordChangeService::class);
    $changedElsewhere = new ReflectionMethod($service, 'changedElsewhere');

    ownerDb()->table('users')->where('id', $user->id)->update([
        'password' => Hash::make(CHANGED_PASSWORD), 'password_changed_at' => now(),
        'password_change_key_hash' => committedKeyHash($user, $key), 'password_change_previous_hash' => $user->password,
    ]);

    $result = $changedElsewhere->invoke($service, $user, committedKeyHash($user, $key), UserFactory::TEST_PASSWORD, CHANGED_PASSWORD);

    expect($result->status)->toBe(PasswordChangeResult::CHANGED)
        ->and($result->replayed)->toBeTrue()
        ->and(eventsOf('auth.password_changed'))->toBe(0);
});

// ---- C': the answer to the commit was lost --------------------------------------------------------

function afterLostCommit(User $user, string $keyHash, string $newHash): PasswordChangeResult
{
    $service = app(PasswordChangeService::class);
    $pdo = new PDOException('lost');
    $pdo->errorInfo = ['HY000', 7, 'server closed the connection unexpectedly'];

    return (new ReflectionMethod($service, 'afterDatabaseError'))
        ->invoke($service, new QueryException('pgsql', 'COMMIT', [], $pdo), $user, $keyHash, $newHash);
}

it("C': the key found on a new connection proves the commit", function () {
    $hash = Hash::make(CHANGED_PASSWORD);
    $keyHash = committedKeyHash($this->user, 'k');

    ownerDb()->table('users')->where('id', $this->user->id)->update([
        'password' => $hash, 'password_changed_at' => now(), 'password_change_key_hash' => $keyHash,
    ]);

    expect(afterLostCommit($this->user, $keyHash, $hash)->status)->toBe(PasswordChangeResult::CHANGED);
});

it("C': no key means unknown: 503, and so does a failing read", function () {
    $hash = Hash::make(CHANGED_PASSWORD);
    $keyHash = committedKeyHash($this->user, 'k');

    expect(fn () => afterLostCommit($this->user, $keyHash, $hash))->toThrow(ServiceUnavailableException::class);

    config(['database.connections.pgsql_audit_read.port' => 1]);
    DB::purge('pgsql_audit_read');

    expect(fn () => afterLostCommit($this->user, $keyHash, $hash))->toThrow(ServiceUnavailableException::class);
});

// ---- rollBack() fails too: the first failure is what counts ------------------------------------

function failRollBacks(): void
{
    $settings = config('database.connections.pgsql');

    DB::connection('pgsql')->setPdo(new ThrowingRollbackPdo(
        "pgsql:host={$settings['host']};port={$settings['port']};dbname={$settings['database']}",
        $settings['username'],
        $settings['password'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
    ));
}

it('the framework replaces the first failure when rollBack() fails, which is why this exists', function () {
    failRollBacks();

    try {
        expect(fn () => DB::connection('pgsql')->transaction(fn () => throw new RuntimeException('first'), 1))
            ->toThrow(PDOException::class, 'no connection');
    } finally {
        DB::purge('pgsql');
    }
});

it('keeps the first failure when rollBack() fails, and leaves no transaction open', function () {
    failRollBacks();

    try {
        expect(fn () => SingleAttemptTransaction::run(DB::connection('pgsql'), fn () => throw new RuntimeException('first')))
            ->toThrow(RuntimeException::class, 'first')
            ->and(DB::connection('pgsql')->transactionLevel())->toBe(0);
    } finally {
        DB::purge('pgsql');
    }
});

it('returns what the callback returns, and commits', function () {
    $organization = insertOrganization(appDb());
    $value = SingleAttemptTransaction::run(appDb(), function ($db) use ($organization) {
        appendAudit(['organization' => $organization], $db);

        return 'done';
    });

    expect($value)->toBe('done')
        ->and(appDb()->table('audit_logs')->where('organization_id', $organization)->count())->toBe(1);

    resetAuditTables();
    ownerDb()->table('organizations')->where('id', $organization)->delete();
});

it('AUDIT-CODE-01: a lock timeout stays a lock timeout when rollBack() fails: no probe, no state', function () {
    useAuditWriter(new FailingAuditWriter('55P03'));
    config(['database.connections.pgsql_audit_read.port' => 1]);
    DB::purge('pgsql_audit_read');
    $logs = captureLogs();
    failRollBacks();

    try {
        $recorded = app(AuditLogger::class)->recordAfterTransaction(AuditEntry::system(AuditEventType::Locked), 'x');
    } finally {
        DB::purge('pgsql');
    }

    $availability = app(AuditAvailability::class);

    expect($recorded)->toBeFalse()
        ->and(linesWithMetric($logs, 'audit.write_failed')[0]->context)->toMatchArray(['sqlstate' => '55P03', 'failure_class' => 'transient'])
        ->and($availability->dbFlagged())->toBeFalse()
        ->and($availability->auditState())->toBeNull();
});

it('AUDIT-FAIL-01: a login whose record fails still reports that when rollBack() fails', function () {
    useAuditWriter(new FailingAuditWriter('55P03', only: [AuditEventType::Login]));
    failRollBacks();

    try {
        expect(fn () => app(LoginService::class)->attempt($this->user->email, UserFactory::TEST_PASSWORD))
            ->toThrow(ServiceUnavailableException::class);
    } finally {
        DB::purge('pgsql');
    }

    expect($this->user->fresh()->last_login_at)->toBeNull();
});

it('AUDIT-RECOVER-01: SF001 is still seen when rollBack() fails', function () {
    Cache::put('audit:unavailable', ['outage_id' => 'o', 'failure_class' => 'storage', 'storage_scope' => 'db_suspected', 'started_at' => 0, 'next_check_at' => 0], 600);
    useAuditWriter(new FailingAuditWriter('SF001'));
    app()->instance(AuditAvailability::class, new AuditAvailability(new FailingAuditWriter('SF001'), app(OutageLog::class)));
    $logs = captureLogs();
    failRollBacks();

    try {
        expect(fn () => app(AuditAvailability::class)->assertAvailable())->toThrow(ServiceUnavailableException::class);
    } finally {
        DB::purge('pgsql');
    }

    expect(linesWithMetric($logs, 'audit.recovery_check_conflict'))->toHaveCount(1);
});

// ---- the state cannot be saved or read ------------------------------------------------------------

it('AUDIT-AVAIL-01: a flag that cannot be saved does not change the outcome, and is logged', function () {
    config(['database.connections.pgsql_audit_read.port' => 1]);
    DB::purge('pgsql_audit_read');
    $logs = captureLogs();
    Cache::shouldReceive('put')->andThrow(new RedisException('Connection lost'));

    $pdo = new PDOException('lost');
    $pdo->errorInfo = ['HY000', 7, 'server closed the connection unexpectedly'];

    app(AuditAvailability::class)->reportWriteFailure(new QueryException('pgsql', 'x', [], $pdo), AuditEntry::system(AuditEventType::Locked), 'x');

    expect(linesWithMetric($logs, 'audit.state_update_failed'))->toHaveCount(1);
});

it('AUDIT-MON-01: a state that cannot be read is unknown, never healthy', function () {
    $logs = captureLogs();
    Cache::shouldReceive('get')->andThrow(new RedisException('Connection lost'));

    Artisan::call('audit:housekeeping');

    expect(linesWithMetric($logs, 'audit.unavailable')[0]->context['value'])->toBe('unknown')
        ->and(Artisan::call('audit:status'))->toBe(2);
});
