<?php

use App\Audit\AuditEventType;
use App\Audit\AuditWriter;
use App\Domain\Auth\AuthenticatedSession;
use App\Domain\Auth\RedisPendingFingerprintStore;
use App\Domain\Auth\RedisRetiredSessions;
use App\Domain\Auth\RetiredSessions;
use App\Http\Middleware\StartSessionUnlessRetired;
use App\Models\User;
use App\Support\Http\ProblemDetails;
use App\Support\Http\ServiceUnavailableException;
use App\Support\Session\RetirementAwareSessionHandler;
use Database\Factories\UserFactory;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Session\CacheBasedSessionHandler;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Redis;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Ramsey\Uuid\Uuid;
use Tests\Support\FailingAuditWriter;
use Tests\Support\FailingWriteSessionHandler;
use Tests\Support\SpaClient;
use Tests\TestCase;

/*
| AUDIT-PWCHG-01 (docs/test-strategy.md §15, docs/security-design.md §16.5.5).
| The commit is the only point of truth. Redis never decides whether a change happened.
*/

uses(DatabaseTransactions::class);

const NEW_PASS = 'a brand new pass phrase';

function changeWithKey(SpaClient $client, string $key, string $new = NEW_PASS, string $current = UserFactory::TEST_PASSWORD): TestResponse
{
    return $client->send('PATCH', '/api/v1/account/password', ['current_password' => $current, 'new_password' => $new], ['HTTP_IDEMPOTENCY_KEY' => $key]);
}

/** The session middleware still has to pass, so the failure comes from the password endpoint itself. */
function loggedInBeforeOutage(SpaClient $client): SpaClient
{
    app('session')->driver()->getHandler()->failing = false;

    return $client;
}

function newKey(): string
{
    return Uuid::uuid7()->toString();
}

function changedEvents(User $user): int
{
    return DB::table('audit_logs')->where('organization_id', $user->organization_id)->where('event_type', 'auth.password_changed')->count();
}

/** Sessions stop saving, the way they do when Redis stops. The database still works. */
function failSessionSave(): FailingWriteSessionHandler
{
    $store = app('session')->driver();
    $handler = new FailingWriteSessionHandler($store->getHandler());
    $store->setHandler($handler);

    return $handler;
}

// ---- the key ------------------------------------------------------------------------------------

it('requires a UUID as Idempotency-Key', function (array $headers) {
    $client = loggedIn($this, User::factory()->create());

    $client->send('PATCH', '/api/v1/account/password', ['current_password' => UserFactory::TEST_PASSWORD, 'new_password' => NEW_PASS], $headers)
        ->assertStatus(422)
        ->assertJsonStructure(['errors' => ['idempotency_key']]);
})->with([
    'missing' => [[]],
    'not a UUID' => [['HTTP_IDEMPOTENCY_KEY' => 'abc']],
]);

it('stores the key only as a keyed hash, and neither column leaves the server', function () {
    $user = User::factory()->create();
    $key = newKey();
    $previous = $user->password;

    $response = changeWithKey(loggedIn($this, $user), $key)->assertOk();

    $row = DB::table('users')->where('id', $user->id)->first();

    expect($row->password_change_key_hash)->toMatch('/^[0-9a-f]{64}$/')
        ->and($row->password_change_key_hash)->not->toContain($key)
        ->and($row->password_change_key_hash)->not->toBe(hash('sha256', $key))
        ->and($row->password_change_previous_hash)->toBe($previous)
        ->and($response->getContent())->not->toContain('password_change_key_hash')->not->toContain($previous)
        ->and(array_keys($user->fresh()->toArray()))->not->toContain('password_change_key_hash', 'password_change_previous_hash', 'password');
});

// ---- A, C: the database rolled back -------------------------------------------------------------

it('Redis fails before the commit: no change, 503, and the same key works afterwards', function (string $failure) {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    $key = newKey();
    pendingStore()->{$failure} = true;

    $response = changeWithKey($client, $key);

    $response->assertStatus(503)->assertHeader('Retry-After')->assertJsonPath('detail', ProblemDetails::PASSWORD_CHANGE_UNAVAILABLE_DETAIL);

    $row = DB::table('users')->where('id', $user->id)->first();
    expect(Hash::check(UserFactory::TEST_PASSWORD, $row->password))->toBeTrue()
        ->and($row->password_changed_at)->toBeNull()
        ->and($row->password_change_key_hash)->toBeNull()
        ->and(changedEvents($user))->toBe(0);

    pendingStore()->{$failure} = false;

    changeWithKey($client, $key)->assertOk();
    expect(changedEvents($user))->toBe(1);
})->with(['failPrepare', 'failWrite']);

it('A: the fingerprint was saved and the database rolled back: not treated as done, and not usable', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    $other = loggedIn($this, $user, ip: '203.0.113.77');
    $key = newKey();
    useAuditWriter(new FailingAuditWriter('55P03', only: [AuditEventType::PasswordChanged]));
    $logs = captureLogs();

    changeWithKey($client, $key)->assertStatus(503);

    $row = DB::table('users')->where('id', $user->id)->first();
    expect(Hash::check(UserFactory::TEST_PASSWORD, $row->password))->toBeTrue()
        ->and($row->password_change_key_hash)->toBeNull()
        ->and(pendingStore()->values)->not->toBeEmpty()
        ->and(linesWithMetric($logs, 'audit.write_failed')[0]->context['outcome'])->toBe('password_change_rolled_back');

    // Everything still works with the old password, and the leftover grants nothing.
    $client->send('GET', '/api/v1/auth/me')->assertOk();
    $other->send('GET', '/api/v1/auth/me')->assertOk();
    spaLogin(spa($this, ip: '203.0.113.78'), $user->email, NEW_PASS)->assertStatus(401);
    spaLogin(spa($this, ip: '203.0.113.79'), $user->email)->assertOk();

    // The leftover does not get in the way of a retry, which then runs once.
    useAuditWriter(new AuditWriter);
    changeWithKey($client, $key)->assertOk();

    expect(changedEvents($user))->toBe(1)
        ->and(Hash::check(NEW_PASS, $user->fresh()->password))->toBeTrue();
});

it('a pending fingerprint for a hash that was never committed does not authenticate', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);

    useAuditWriter(new FailingAuditWriter('55P03', only: [AuditEventType::PasswordChanged]));
    changeWithKey($client, newKey())->assertStatus(503);
    expect(pendingStore()->values)->not->toBeEmpty();

    // Someone else changes the password: the session no longer matches, and the leftover does not either.
    DB::table('users')->where('id', $user->id)->update(['password' => Hash::make('changed behind the session')]);

    $client->send('GET', '/api/v1/auth/me')->assertStatus(401);
});

// ---- B: committed, response lost ----------------------------------------------------------------

it('B: the same key and content do not run again, and answer the same time', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    $key = newKey();

    $first = changeWithKey($client, $key)->assertOk();
    $hash = $user->fresh()->password;

    $second = changeWithKey($client, $key)->assertOk();

    expect($second->json('data.password_changed_at'))->toBe($first->json('data.password_changed_at'))
        ->and($user->fresh()->password)->toBe($hash)
        ->and(changedEvents($user))->toBe(1);
});

it('B: another key does not change it again', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);

    changeWithKey($client, newKey())->assertOk();
    $hash = $user->fresh()->password;

    changeWithKey($client, newKey())->assertStatus(422)->assertJsonPath('code', 'CURRENT_PASSWORD_INVALID');

    expect($user->fresh()->password)->toBe($hash)->and(changedEvents($user))->toBe(1);
});

// ---- E: every condition -------------------------------------------------------------------------

it('E: with the fingerprint gone the session ends, and after logging in again the database alone decides', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    $key = newKey();
    $handler = failSessionSave();

    changeWithKey($client, $key)->assertStatus(503)->assertJsonPath('detail', ProblemDetails::PASSWORD_CHANGE_UNAVAILABLE_DETAIL);

    $handler->failing = false;
    pendingStore()->values = [];

    $client->send('GET', '/api/v1/auth/me')->assertStatus(401);
    spaLogin(spa($this, ip: '203.0.113.81'), $user->email)->assertStatus(401);
    $again = loggedIn($this, $user, NEW_PASS, '203.0.113.82');

    changeWithKey($again, $key)->assertOk();

    expect(changedEvents($user))->toBe(1)
        ->and(Hash::check(NEW_PASS, $user->fresh()->password))->toBeTrue();
});

it('E: a retry without a session is not authentication', function () {
    $user = User::factory()->create();
    $key = newKey();
    changeWithKey(loggedIn($this, $user), $key)->assertOk();

    changeWithKey(spa($this, ip: '203.0.113.83')->csrf(), $key)->assertStatus(401);
});

it('E: is not done unless all four conditions hold', function (Closure $breakIt, int $status) {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    $key = newKey();
    changeWithKey($client, $key)->assertOk();
    $hash = $user->fresh()->password;

    $breakIt($client, $key, $user, $this)->assertStatus($status);

    expect($user->fresh()->password)->toBe($hash)->and(changedEvents($user))->toBe(1);
})->with([
    'new_password differs' => [fn (SpaClient $c, string $k) => changeWithKey($c, $k, 'yet another pass phrase'), 409],
    'current_password differs' => [fn (SpaClient $c, string $k) => changeWithKey($c, $k, current: 'not the old password'), 409],
    'the key differs' => [fn (SpaClient $c, string $k) => changeWithKey($c, newKey()), 422],
    'the window has passed, with the columns still there' => [function (SpaClient $c, string $k, User $u) {
        DB::table('users')->where('id', $u->id)->update(['password_changed_at' => now()->subMinutes(16)]);

        return changeWithKey($c, $k);
    }, 422],
    'APP_KEY rotated' => [function (SpaClient $c, string $k, User $u, TestCase $test) {
        // The hash no longer matches. Sessions depend on the same key, so a new login comes first.
        $rotated = 'base64:'.base64_encode(random_bytes(32));
        config(['app.key' => $rotated]);
        app()->forgetInstance('encrypter');
        $client = loggedIn($test, $u, NEW_PASS, '203.0.113.90');

        return changeWithKey($client, $k);
    }, 422],
]);

it('the scheduler only tidies up: it leaves rows inside the window, and clears those outside', function () {
    $inside = User::factory()->create();
    $outside = User::factory()->create();
    changeWithKey(loggedIn($this, $inside, ip: '203.0.113.91'), newKey())->assertOk();
    changeWithKey(loggedIn($this, $outside, ip: '203.0.113.92'), newKey())->assertOk();
    DB::table('users')->where('id', $outside->id)->update(['password_changed_at' => now()->subMinutes(16)]);

    Artisan::call('audit:housekeeping');

    expect(DB::table('users')->where('id', $inside->id)->value('password_change_previous_hash'))->not->toBeNull()
        ->and(DB::table('users')->where('id', $outside->id)->value('password_change_previous_hash'))->toBeNull()
        ->and(DB::table('users')->where('id', $outside->id)->value('password_change_key_hash'))->toBeNull();
});

it('another change replaces both columns together', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    $firstKey = newKey();

    changeWithKey($client, $firstKey)->assertOk();
    $firstHash = $user->fresh()->password;
    $firstKeyHash = DB::table('users')->where('id', $user->id)->value('password_change_key_hash');

    changeWithKey($client, newKey(), 'the second pass phrase here', NEW_PASS)->assertOk();

    expect(DB::table('users')->where('id', $user->id)->value('password_change_previous_hash'))->toBe($firstHash)
        ->and(DB::table('users')->where('id', $user->id)->value('password_change_key_hash'))->not->toBe($firstKeyHash);

    changeWithKey($client, $firstKey)->assertStatus(422);
});

// ---- after the commit ---------------------------------------------------------------------------

it('the commit stands when the session cannot be saved: 503, no undo, and a retry completes it', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    $key = newKey();
    $cookieBefore = $client->sessionCookie();
    $retiredBefore = retiredSessions()->ids;
    $handler = failSessionSave();
    $logs = captureLogs();

    $response = changeWithKey($client, $key)
        ->assertStatus(503)
        ->assertHeader('Retry-After')
        ->assertJsonPath('code', 'SERVICE_UNAVAILABLE')
        ->assertJsonPath('detail', ProblemDetails::PASSWORD_CHANGE_UNAVAILABLE_DETAIL);

    $hash = $user->fresh()->password;

    expect(Hash::check(NEW_PASS, $hash))->toBeTrue()
        ->and(changedEvents($user))->toBe(1)
        // Not stored, so the right to rotate goes back: the session must not be stuck after recovery.
        ->and(retiredSessions()->ids)->toBe($retiredBefore)
        // A cookie for an id that was not stored must never be sent.
        ->and($client->sessionCookie())->toBe($cookieBefore)
        ->and(array_map(fn ($cookie) => $cookie->getName(), $response->baseResponse->headers->getCookies()))
        ->not->toContain(config('session.cookie'))
        ->and(linesWithMetric($logs, 'auth.password_change_session_failed')[0]->context['outcome'])->toBe('password_change_committed_session_failed')
        // Nothing about completed keys is kept in Redis: the row alone answers a retry.
        ->and(json_encode(pendingStore()->values))->not->toContain($key);

    // Still failing: 503 again, and the database does not move.
    changeWithKey($client, $key)->assertStatus(503);
    expect($user->fresh()->password)->toBe($hash)->and(changedEvents($user))->toBe(1);

    $handler->failing = false;

    // The saved fingerprint keeps this session valid once it matches the committed hash.
    $client->send('GET', '/api/v1/auth/me')->assertOk();
    changeWithKey($client, $key)->assertOk();

    $logged = implode("\n", array_map(fn ($line) => $line->message.json_encode($line->context), (array) $logs));

    expect($user->fresh()->password)->toBe($hash)
        ->and(changedEvents($user))->toBe(1)
        ->and($client->sessionCookie())->not->toBe($cookieBefore)
        ->and($logged)->not->toContain($key)->not->toContain(NEW_PASS)->not->toContain($hash);
});

it('the other sessions end on the commit alone, with nothing removed from the session store', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user, ip: '203.0.113.93');
    $other = loggedIn($this, $user, ip: '203.0.113.94');
    $handler = failSessionSave();

    changeWithKey($client, newKey())->assertStatus(503);

    $handler->failing = false;

    $other->send('GET', '/api/v1/auth/me')->assertStatus(401);
});

it('every 503 of this endpoint says the same thing, before and after the commit', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);

    pendingStore()->failWrite = true;
    $before = changeWithKey($client, newKey())->assertStatus(503);
    pendingStore()->failWrite = false;

    failSessionSave();
    $after = changeWithKey($client, newKey())->assertStatus(503);

    Cache::put('audit:unavailable', ['outage_id' => 'o', 'failure_class' => 'storage', 'storage_scope' => 'db_suspected', 'started_at' => 0, 'next_check_at' => PHP_INT_MAX], 600);
    $preflight = changeWithKey(loggedInBeforeOutage($client), newKey())->assertStatus(503);

    foreach (['type', 'title', 'status', 'code', 'detail'] as $field) {
        expect($after->json($field))->toBe($before->json($field))
            ->and($preflight->json($field))->toBe($before->json($field));
    }

    expect($before->json('detail'))->toBe('パスワード変更の結果を確認できませんでした。変更が確定している可能性があります。できるだけ早く、同じ内容・同じ冪等性キーで再試行してください。')
        ->and($before->headers->get('Retry-After'))->toBe($after->headers->get('Retry-After'))
        ->and($before->headers->get('Content-Type'))->toBe('application/problem+json');
});

it('other endpoints keep their own 503 wording', function () {
    useAuditWriter(new FailingAuditWriter('55P03'));

    $detail = spaLogin(spa($this, ip: '203.0.113.95'), User::factory()->create()->email)->assertStatus(503)->json('detail');

    expect($detail)->not->toBe(ProblemDetails::PASSWORD_CHANGE_UNAVAILABLE_DETAIL);
});

// ---- AUDIT-SESSION-01 ------------------------------------------------------------------------------

it('AUDIT-SESSION-01: the changing session stays, older sessions end, a new login can retry', function () {
    $user = User::factory()->create();
    $a = loggedIn($this, $user, ip: '203.0.113.21');
    $b = loggedIn($this, $user, ip: '203.0.113.22');
    $d = loggedIn($this, $user, ip: '203.0.113.23');
    $key = newKey();

    $at = changeWithKey($a, $key)->assertOk()->json('data.password_changed_at');
    $hash = $user->fresh()->password;

    $a->send('GET', '/api/v1/auth/me')->assertOk();
    $b->send('GET', '/api/v1/auth/me')->assertStatus(401);
    changeWithKey($d, $key)->assertStatus(401);
    $d->send('GET', '/api/v1/auth/me')->assertStatus(401);

    $c = loggedIn($this, $user, NEW_PASS, '203.0.113.24');
    expect(changeWithKey($c, $key)->assertOk()->json('data.password_changed_at'))->toBe($at);
    $c->send('GET', '/api/v1/auth/me')->assertOk();
    $a->send('GET', '/api/v1/auth/me')->assertOk();

    expect($user->fresh()->password)->toBe($hash)->and(changedEvents($user))->toBe(1);
});

it('AUDIT-SESSION-01: the session id is rotated once, and a retry on the old id gets 401 with no new session', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    $stale = spa($this);
    $stale->useCookies($client->cookies());
    $key = newKey();
    $retiredBefore = count(retiredSessions()->ids);

    changeWithKey($client, $key)->assertOk();

    expect(retiredSessions()->ids)->toHaveCount($retiredBefore + 1);

    $response = changeWithKey($stale, $key)->assertStatus(401);

    expect(array_map(fn ($cookie) => $cookie->getName(), $response->baseResponse->headers->getCookies()))->not->toContain(config('session.cookie'))
        ->and(changedEvents($user))->toBe(1);

    $client->send('GET', '/api/v1/auth/me')->assertOk();
});

it('AUDIT-SESSION-01: nothing the old id does afterwards writes it back or sends its cookie', function () {
    $client = loggedIn($this, User::factory()->create());
    $stale = spa($this);
    $stale->useCookies($client->cookies());
    $before = $stale->sessionCookie();

    changeWithKey($client, newKey())->assertOk();

    foreach ([['GET', '/api/v1/auth/me'], ['GET', '/sanctum/csrf-cookie'], ['POST', '/api/v1/auth/logout']] as [$method, $uri]) {
        $stale->send($method, $uri);

        expect($stale->sessionCookie())->toBe($before, $uri);
    }

    $stale->send('GET', '/api/v1/auth/me')->assertStatus(401);
    $client->send('GET', '/api/v1/auth/me')->assertOk();
});

it('AUDIT-SESSION-02: the session middleware and the Redis handler in use are the ones that refuse a retired id', function () {
    config(['session.driver' => 'redis']);
    app('session')->forgetDrivers();

    expect(app(StartSession::class))->toBeInstanceOf(StartSessionUnlessRetired::class)
        ->and(app('session')->driver()->getHandler())->toBeInstanceOf(RetirementAwareSessionHandler::class);

    config(['session.driver' => 'array']);
    app('session')->forgetDrivers();
});

it('AUDIT-SESSION-02: a logout retires the id: the old cookie gets 401, with no cookie and nothing stored', function () {
    $client = loggedIn($this, User::factory()->create());
    $stale = spa($this);
    $stale->useCookies($client->cookies());
    $before = $stale->sessionCookie();

    $response = $client->send('POST', '/api/v1/auth/logout')->assertNoContent();

    expect(array_map(fn ($cookie) => $cookie->getName(), $response->baseResponse->headers->getCookies()))->toContain(config('session.cookie'))
        ->and(retiredSessions()->ids)->not->toBeEmpty();

    $stale->send('GET', '/api/v1/auth/me')->assertStatus(401);
    expect($stale->sessionCookie())->toBe($before);

    // The browser that logged out has a new session, and can use it.
    spaLogin($client, User::factory()->create()->email)->assertOk();
    $client->send('GET', '/api/v1/auth/me')->assertOk();
});

it('AUDIT-SESSION-02: a request running when its id is retired answers, but saves nothing and sends no session cookies', function () {
    $client = loggedIn($this, User::factory()->create());
    $id = null;

    Route::middleware('api')->get('/api/test-retired-while-running', function (Request $request) use (&$id) {
        $id = $request->session()->getId();
        $request->session()->put('written', 'after the end');
        app(RetiredSessions::class)->retire($id);
        $request->session()->getHandler()->destroy($id);

        return response()->json(['status' => 'answered']);
    });

    $response = $client->send('GET', '/api/test-retired-while-running')->assertOk();

    expect(array_map(fn ($cookie) => $cookie->getName(), $response->baseResponse->headers->getCookies()))->toBe([])
        ->and(app('session')->driver()->getHandler()->read($id))->toBe('');
});

it('AUDIT-SESSION-02: a login retires the session it replaces', function () {
    $client = spa($this);
    $client->csrf();
    $stale = spa($this);
    $stale->useCookies($client->cookies());
    $before = $stale->sessionCookie();

    $retiredBefore = count(retiredSessions()->ids);

    spaLogin($client, User::factory()->create()->email)->assertOk();

    expect(retiredSessions()->ids)->toHaveCount($retiredBefore + 1);

    $stale->send('GET', '/api/v1/auth/me')->assertStatus(401);
    expect($stale->sessionCookie())->toBe($before);
});

it('AUDIT-SESSION-02: ending a session that a parallel request already ended creates no new one', function () {
    $client = loggedIn($this, User::factory()->create());
    $ids = [];

    Route::middleware(['api', 'auth:sanctum'])->get('/api/test-ended-twice', function (Request $request) use (&$ids) {
        $ids[] = $request->session()->getId();
        retiredSessions()->retire($ids[0]);
        app(AuthenticatedSession::class)->end($request);
        $ids[] = $request->session()->getId();

        return response()->json(['status' => 'answered']);
    });

    $response = $client->send('GET', '/api/test-ended-twice')->assertOk();

    expect($ids[1])->toBe($ids[0])
        ->and(array_map(fn ($cookie) => $cookie->getName(), $response->baseResponse->headers->getCookies()))->toBe([]);
});

// ---- AUDIT-CSRF-01 ---------------------------------------------------------------------------------

it('AUDIT-CSRF-01: a state change without a login is 401, with or without a token', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    $ended = spa($this);
    $ended->useCookies($client->cookies());
    $client->send('POST', '/api/v1/auth/logout')->assertNoContent();

    $ended->send('GET', '/api/v1/auth/me')->assertStatus(401);
    $ended->send('PATCH', '/api/v1/account/password', ['current_password' => 'x', 'new_password' => 'y'], ['HTTP_IDEMPOTENCY_KEY' => newKey()])->assertStatus(401)->assertJsonPath('code', 'UNAUTHENTICATED');
    $ended->send('POST', '/api/v1/auth/logout')->assertStatus(401);

    $none = spa($this, ip: '203.0.113.26');
    $none->send('PATCH', '/api/v1/account/password', ['current_password' => 'x', 'new_password' => 'y'])->assertStatus(401);
    $none->send('POST', '/api/v1/auth/logout')->assertStatus(401);
});

it('AUDIT-CSRF-01: a session with a login, and the login route, are still checked', function () {
    $client = loggedIn($this, User::factory()->create());
    $client->forgetCsrfCookie();

    $client->send('POST', '/api/v1/auth/logout')->assertStatus(419)->assertJsonPath('code', 'CSRF_TOKEN_MISMATCH');
    $client->send('PATCH', '/api/v1/account/password', ['current_password' => 'x', 'new_password' => 'y'], ['HTTP_IDEMPOTENCY_KEY' => newKey()])->assertStatus(419);
    $client->send('GET', '/api/v1/auth/me')->assertOk();

    spa($this, ip: '203.0.113.27')->send('POST', '/api/v1/auth/login', ['email' => 'a@example.com', 'password' => 'x'])->assertStatus(419);
});

// ---- concurrency --------------------------------------------------------------------------------

it('holds no audit head lock while writing to Redis', function () {
    $source = (string) file_get_contents(app_path('Domain/Auth/PasswordChangeService.php'));

    expect(strpos($source, 'pending->write'))->toBeLessThan(strpos($source, 'recordInTransaction'));
});

it('does not use Connection::command() under the row lock', function () {
    $source = (string) file_get_contents(app_path('Domain/Auth/RedisPendingFingerprintStore.php'));

    expect($source)->not->toMatch('/->command\(/')
        ->and($source)->toContain('hrtime(')
        ->and(config('database.redis.pending.max_retries'))->toBe(0)
        ->and((float) config('database.redis.pending.read_timeout'))->toBe(0.9);
});

// ---- the real store, against the real Redis -------------------------------------------------------

it('the real store writes on the connection it checked, with an expiry', function () {
    $store = new RedisPendingFingerprintStore;
    $sessionId = 'test-'.newKey();

    $store->prepare();
    $connection = Redis::connection('pending')->client();
    $before = $connection->rawCommand('CLIENT', 'ID');

    $store->write($sessionId, 'fingerprint', 'owner');

    expect($before)->toBeInt()
        ->and($connection->rawCommand('CLIENT', 'ID'))->toBe($before)
        ->and($store->read($sessionId))->toBe('fingerprint')
        ->and($connection->ttl('password_pending:'.hash('sha256', $sessionId)))->toBeGreaterThan(1800);

    $connection->del('password_pending:'.hash('sha256', $sessionId));
});

it('the real store keeps others from rotating while the writer may finish', function () {
    $store = new RedisPendingFingerprintStore;
    $sessionId = 'test-'.newKey();

    $store->prepare();
    $store->write($sessionId, 'fingerprint', 'writer');

    expect($store->mayRotate($sessionId, 'another'))->toBeFalse()
        ->and($store->mayRotate($sessionId, null))->toBeFalse()
        ->and($store->mayRotate($sessionId, 'writer'))->toBeTrue()
        ->and($store->read($sessionId))->toBe('fingerprint');

    // The writer could not store the session: the fingerprint stays, and anyone may finish now.
    $store->giveUpOwnership($sessionId);

    expect($store->mayRotate($sessionId, null))->toBeTrue()
        ->and($store->read($sessionId))->toBe('fingerprint');

    Redis::connection('pending')->client()->del('password_pending:'.hash('sha256', $sessionId));
});

it('the real store lets others rotate once the writer has had its time', function () {
    $store = new RedisPendingFingerprintStore;
    $sessionId = 'test-'.newKey();

    $store->prepare();
    $store->write($sessionId, 'fingerprint', 'writer');
    $this->travel(16)->seconds();

    expect($store->mayRotate($sessionId, null))->toBeTrue();

    Redis::connection('pending')->client()->del('password_pending:'.hash('sha256', $sessionId));
});

it('AUDIT-SESSION-02: the real store retires an id, gives the claim to one, and can give it back', function () {
    $retired = new RedisRetiredSessions;
    $sessionId = 'test-'.newKey();

    expect($retired->isRetired($sessionId))->toBeFalse()
        ->and($retired->claim($sessionId))->toBeTrue()
        ->and($retired->claim($sessionId))->toBeFalse()
        ->and($retired->isRetired($sessionId))->toBeTrue()
        ->and(Redis::connection(RedisRetiredSessions::CONNECTION)->client()->ttl(RedisRetiredSessions::key($sessionId)))->toBeGreaterThan(1800);

    $retired->restore($sessionId);

    expect($retired->isRetired($sessionId))->toBeFalse();

    $retired->retire($sessionId);

    expect($retired->isRetired($sessionId))->toBeTrue();

    $retired->restore($sessionId);
});

it('AUDIT-SESSION-02: on real Redis the handler stores like Laravel, and a retired id cannot be written back', function () {
    $store = clone Cache::store('redis');
    $store->getStore()->setConnection('session');
    $handler = new RetirementAwareSessionHandler($store, 30);
    $plain = new CacheBasedSessionHandler($store, 30);
    $retired = new RedisRetiredSessions;
    $sessionId = 'test-'.newKey();
    $client = Redis::connection('session')->client();

    expect($handler->write($sessionId, 'a:1:{s:1:"a";i:1;}'))->toBeTrue()
        ->and($plain->read($sessionId))->toBe('a:1:{s:1:"a";i:1;}')
        ->and($handler->read($sessionId))->toBe('a:1:{s:1:"a";i:1;}');

    expect($client->ttl($store->getStore()->getPrefix().$sessionId))->toBeGreaterThan(1700)->toBeLessThanOrEqual(1800);

    $retired->retire($sessionId);
    $handler->destroy($sessionId);

    expect($handler->write($sessionId, 'a:1:{s:1:"a";i:2;}'))->toBeFalse()
        ->and($handler->read($sessionId))->toBe('');

    $retired->restore($sessionId);
});

it('the real store does not reconnect after losing its connection, and fails at once', function () {
    $store = new RedisPendingFingerprintStore;
    $store->prepare();
    $connection = Redis::connection('pending')->client();
    $id = $connection->rawCommand('CLIENT', 'ID');

    expect(Redis::connection('default')->client()->rawCommand('CLIENT', 'KILL', 'ID', (string) $id))->toBe(1);

    $start = hrtime(true);

    expect(fn () => $store->write('test-'.newKey(), 'fingerprint', 'owner'))->toThrow(ServiceUnavailableException::class);
    expect((hrtime(true) - $start) / 1e9)->toBeLessThan(1.0);

    Redis::purge('pending');
});

it('the real store fails before the lock when Redis is unreachable', function () {
    useRedisSettings(['database.redis.pending.host' => '127.0.0.1', 'database.redis.pending.port' => 1]);

    expect(fn () => (new RedisPendingFingerprintStore)->prepare())->toThrow(ServiceUnavailableException::class);
});

it('treats an overrun as a failure even when the write succeeded', function () {
    config(['audit.password_pending_redis_timeout_ms' => -1]);
    $store = new RedisPendingFingerprintStore;
    $store->prepare();
    $sessionId = 'test-'.newKey();

    expect(fn () => $store->write($sessionId, 'fingerprint', 'owner'))->toThrow(ServiceUnavailableException::class);

    Redis::connection('pending')->client()->del('password_pending:'.hash('sha256', $sessionId));
});
