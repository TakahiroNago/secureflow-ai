<?php

use App\Events\AccountLocked;
use App\Models\User;
use Database\Factories\UserFactory;
use Illuminate\Auth\Events\Failed;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

/*
| ST-05, ST-24 to ST-27 (docs/test-strategy.md §5) and AUTH-ERR, AUTH-LOCK, AUTH-RATE, AUTH-CSRF (§14).
*/

uses(DatabaseTransactions::class);

const LOGIN = '/api/v1/auth/login';
const ME = '/api/v1/auth/me';
const PUBLIC_API_ROUTES = ['api/health/live', 'api/health/ready', 'api/v1/auth/login'];

function problemWithoutTrace(TestResponse $response): array
{
    return collect($response->json())->except('trace_id')->all();
}

// ---- ST-05 ------------------------------------------------------------------------------------

it('ST-05: protects every API route except the public ones, including future routes', function () {
    $apiRoutes = collect(Route::getRoutes()->getRoutes())->filter(fn ($route) => str_starts_with($route->uri(), 'api/'));

    $protected = $apiRoutes->reject(fn ($route) => in_array($route->uri(), PUBLIC_API_ROUTES, true));

    expect($protected->count())->toBeGreaterThanOrEqual(3);

    foreach ($protected as $route) {
        expect($route->gatherMiddleware())->toContain('auth:sanctum', 'session.current');
    }
});

it('ST-05: answers 401 on each protected route without a session', function (string $method, string $uri) {
    $client = spa($this)->csrf();

    $response = $client->send($method, $uri, $method === 'GET' ? null : []);

    $response->assertStatus(401)
        ->assertHeader('Content-Type', 'application/problem+json')
        ->assertJsonPath('code', 'UNAUTHENTICATED');
})->with([
    ['GET', ME],
    ['POST', '/api/v1/auth/logout'],
    ['PATCH', '/api/v1/account/password'],
]);

it('ST-05: answers 401 rather than redirecting when the client does not ask for JSON', function () {
    spa($this)->send('GET', ME, null, ['HTTP_ACCEPT' => 'text/html'])->assertStatus(401);
});

it('ST-05: treats a bearer token as unauthenticated, not as a server error', function () {
    $client = spa($this, origin: null);

    $client->send('GET', ME, null, ['HTTP_AUTHORIZATION' => 'Bearer 1|abcdefghijklmnopqrstuvwxyz'])
        ->assertStatus(401);
});

// ---- ST-27 and AUTH-ERR-01 ---------------------------------------------------------------------

it('ST-27, AUTH-ERR-01: makes every failure identical from outside, whether the address exists or not', function () {
    $wrongPassword = User::factory()->create();
    $inactive = User::factory()->inactive()->create();
    $locked = User::factory()->locked()->create();

    $responses = [
        spaLogin(spa($this), 'nobody@example.com', 'any password at all'),
        spaLogin(spa($this), $wrongPassword->email, 'any password at all'),
        spaLogin(spa($this), $inactive->email),
        spaLogin(spa($this), $locked->email),
    ];

    foreach ($responses as $response) {
        $response->assertStatus(401)->assertHeader('Content-Type', 'application/problem+json');
    }

    $bodies = array_map('problemWithoutTrace', $responses);

    expect($bodies[0])->toMatchArray([
        'type' => 'https://secureflow.local/problems/auth-failed',
        'title' => 'Authentication failed',
        'status' => 401,
        'code' => 'AUTH_FAILED',
    ]);
    expect($bodies[1])->toBe($bodies[0])
        ->and($bodies[2])->toBe($bodies[0])
        ->and($bodies[3])->toBe($bodies[0]);
    expect($responses[0]->json('trace_id'))->not->toBeEmpty();
});

it('AUTH-ERR-01: verifies a password hash in every case, so the time taken gives nothing away', function (string $state) {
    $email = match ($state) {
        'unknown' => 'nobody@example.com',
        'wrong' => User::factory()->create()->email,
        'inactive' => User::factory()->inactive()->create()->email,
        'locked' => User::factory()->locked()->create()->email,
    };
    $hasher = new class(app('hash'))
    {
        public int $checks = 0;

        public function __construct(private readonly object $hasher) {}

        public function check(string $value, ?string $hash, array $options = []): bool
        {
            $this->checks++;

            return $this->hasher->check($value, (string) $hash, $options);
        }

        public function __call(string $method, array $arguments): mixed
        {
            return $this->hasher->{$method}(...$arguments);
        }
    };
    Hash::swap($hasher);

    spaLogin(spa($this), $email, 'any password at all')->assertStatus(401);

    expect($hasher->checks)->toBe(1);
})->with(['unknown', 'wrong', 'inactive', 'locked']);

it('AUTH-ERR-01: rejects the right password for inactive and locked accounts', function (string $factoryState) {
    $user = User::factory()->{$factoryState}()->create();

    spaLogin(spa($this), $user->email)->assertStatus(401)->assertJsonPath('code', 'AUTH_FAILED');
})->with(['inactive', 'locked']);

it('reports a failed login to observers with the address only', function () {
    Event::fake([Failed::class]);

    spaLogin(spa($this), 'nobody@example.com', 'any password at all');

    Event::assertDispatched(Failed::class, fn (Failed $event) => $event->credentials === ['email' => 'nobody@example.com']);
});

// ---- ST-24 and AUTH-LOCK ---------------------------------------------------------------------

/** Each attempt from a new address, so that the rate limit does not interfere. */
function failLogins(TestCase $test, User $user, int $times): void
{
    for ($i = 0; $i < $times; $i++) {
        spaLogin(spa($test, ip: '198.51.100.'.($i + 1)), $user->email, 'wrong password here')->assertStatus(401);
    }
}

it('ST-24: locks the account after five failures, with the same message', function () {
    $user = User::factory()->create();
    Event::fake([AccountLocked::class]);

    failLogins($this, $user, 4);
    expect($user->fresh()->isLocked())->toBeFalse();
    Event::assertNotDispatched(AccountLocked::class);
    $beforeLock = spaLogin(spa($this, ip: '198.51.100.100'), $user->email)->assertOk();

    failLogins($this, $user, 5);

    expect($user->fresh()->isLocked())->toBeTrue()
        ->and($beforeLock->json('data.email'))->toBe($user->email);
    Event::assertDispatched(AccountLocked::class);

    spaLogin(spa($this, ip: '198.51.100.101'), $user->email)
        ->assertStatus(401)
        ->assertJsonPath('code', 'AUTH_FAILED');
});

it('AUTH-LOCK-01: unlocks after 15 minutes, not before', function () {
    $user = User::factory()->create();
    failLogins($this, $user, 5);

    $this->travel(14)->minutes();
    spaLogin(spa($this, ip: '198.51.100.102'), $user->email)->assertStatus(401);

    $this->travel(2)->minutes();
    spaLogin(spa($this, ip: '198.51.100.103'), $user->email)->assertOk();

    expect($user->fresh()->locked_until)->toBeNull();
});

it('AUTH-LOCK-01: further attempts while locked do not extend the lock', function () {
    $user = User::factory()->create();
    failLogins($this, $user, 5);
    $lockedUntil = $user->fresh()->locked_until;

    $this->travel(5)->minutes();
    failLogins($this, $user, 3);

    expect($user->fresh()->locked_until->equalTo($lockedUntil))->toBeTrue();
});

it('AUTH-LOCK-01: a success resets the failure count', function () {
    $user = User::factory()->create();
    failLogins($this, $user, 4);

    spaLogin(spa($this, ip: '198.51.100.104'), $user->email)->assertOk();

    expect($user->fresh()->failed_login_count)->toBe(0)
        ->and($user->fresh()->last_login_at)->not->toBeNull();

    failLogins($this, $user, 4);
    expect($user->fresh()->isLocked())->toBeFalse();
});

it('AUTH-LOCK-01: concurrent failures do not lose a count', function () {
    // Real processes and committed rows, so this test cannot use a transaction.
    DB::connection('pgsql')->rollBack();
    DB::connection('pgsql_migrator')->rollBack();

    $user = User::factory()->create();

    try {
        $script = 'chdir("'.base_path().'"); require "vendor/autoload.php"; $a = require "bootstrap/app.php";'
            .' $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();'
            .' app(App\Domain\Auth\LoginService::class)->recordFailure(App\Models\User::findOrFail("'.$user->id.'"));';

        $results = Process::concurrently(function ($pool) use ($script) {
            foreach (range(1, 4) as $i) {
                $pool->path(base_path())->command(['php', '-r', $script]);
            }
        });

        foreach ($results as $result) {
            expect($result->successful())->toBeTrue();
        }

        expect($user->fresh()->failed_login_count)->toBe(4);
    } finally {
        ownerDb()->table('users')->where('id', $user->id)->delete();
        ownerDb()->table('organizations')->where('id', $user->organization_id)->delete();
        DB::connection('pgsql')->beginTransaction();
        DB::connection('pgsql_migrator')->beginTransaction();
    }
});

it('AUTH-LOCK-02: a lock leaves existing sessions working (T-33)', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);

    failLogins($this, $user, 5);

    expect($user->fresh()->isLocked())->toBeTrue();
    $client->send('GET', ME)->assertOk()->assertJsonPath('data.id', $user->id);
});

// ---- ST-25 ------------------------------------------------------------------------------------

it('ST-25: changes the session ID when logging in', function () {
    $user = User::factory()->create();
    $client = spa($this)->csrf();
    $before = $client->sessionCookie();
    $sessionBefore = decrypt($before, false);

    $client->send('POST', LOGIN, ['email' => $user->email, 'password' => UserFactory::TEST_PASSWORD])->assertOk();

    expect($before)->not->toBeNull()
        ->and(decrypt($client->sessionCookie(), false))->not->toBe($sessionBefore);
});

it('ST-25: the session from before the login does not become authenticated', function () {
    $user = User::factory()->create();
    $client = spa($this)->csrf();
    $cookiesBeforeLogin = $client->cookies();

    $client->send('POST', LOGIN, ['email' => $user->email, 'password' => UserFactory::TEST_PASSWORD])->assertOk();

    $attacker = spa($this);
    $attacker->useCookies($cookiesBeforeLogin);
    $attacker->send('GET', ME)->assertStatus(401);
});

// ---- ST-26 and AUTH-CSRF-01 -------------------------------------------------------------------

it('ST-26: refuses a state change without a CSRF token', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    $client->forgetCsrfCookie();

    $client->send('POST', '/api/v1/auth/logout')
        ->assertStatus(419)
        ->assertHeader('Content-Type', 'application/problem+json')
        ->assertJsonPath('code', 'CSRF_TOKEN_MISMATCH');

    $client->csrf();
    $client->send('GET', ME)->assertOk();
});

it('ST-26: refuses a login without a CSRF token', function () {
    $user = User::factory()->create();

    spa($this)->send('POST', LOGIN, ['email' => $user->email, 'password' => UserFactory::TEST_PASSWORD])
        ->assertStatus(419);
});

it('ST-26: refuses a wrong CSRF token', function () {
    $user = User::factory()->create();
    $client = spa($this)->csrf();

    $client->send('POST', LOGIN, ['email' => $user->email, 'password' => 'x'], ['HTTP_X_XSRF_TOKEN' => 'wrong'])
        ->assertStatus(419);
});

it('AUTH-CSRF-01: gives no session to an origin that is not allowed', function (?string $origin) {
    $user = User::factory()->create();

    spaLogin(spa($this, origin: $origin), $user->email)
        ->assertStatus(419)
        ->assertJsonPath('code', 'CSRF_TOKEN_MISMATCH');

    expect($user->fresh()->last_login_at)->toBeNull();
})->with([
    'another site' => ['https://attacker.example'],
    'similar host' => ['http://localhost:8080.attacker.example'],
    'allowed name, other port' => ['http://localhost:9999'],
    'no origin at all' => [null],
]);

it('AUTH-CSRF-01: a stolen cookie is not accepted from another origin', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);

    $attacker = spa($this, origin: 'https://attacker.example');
    $attacker->useCookies($client->cookies());

    $attacker->send('GET', ME)->assertStatus(401);
});

it('AUTH-CSRF-01: works from both allowed frontends', function (string $origin) {
    $user = User::factory()->create();

    spaLogin(spa($this, origin: $origin), $user->email)->assertOk();
})->with(['http://localhost:8080', 'http://127.0.0.1:8080', 'http://localhost:5173', 'http://127.0.0.1:5173']);

it('AUTH-CSRF-01: lists explicit host and port pairs, with no wildcard', function () {
    $domains = config('sanctum.stateful');

    expect($domains)->not->toBeEmpty();
    foreach ($domains as $domain) {
        expect($domain)->not->toContain('*')->toMatch('/^[a-z0-9.-]+:\d+$/');
    }
});

// ---- AUTH-RATE-01 -----------------------------------------------------------------------------

it('AUTH-RATE-01: answers 429 with Retry-After on the sixth attempt', function () {
    $client = spa($this)->csrf();

    foreach (range(1, 5) as $ignored) {
        $client->send('POST', LOGIN, ['email' => 'nobody@example.com', 'password' => 'any password at all'])->assertStatus(401);
    }

    $client->send('POST', LOGIN, ['email' => 'nobody@example.com', 'password' => 'any password at all'])
        ->assertStatus(429)
        ->assertHeader('Retry-After')
        ->assertHeader('Content-Type', 'application/problem+json')
        ->assertJsonPath('code', 'RATE_LIMITED');
});

it('AUTH-RATE-01: X-Forwarded-For cannot be used to get around the limit', function () {
    $client = spa($this)->csrf();

    foreach (range(1, 5) as $i) {
        $client->send('POST', LOGIN, ['email' => 'nobody@example.com', 'password' => 'any password at all'], ['HTTP_X_FORWARDED_FOR' => "192.0.2.{$i}"])
            ->assertStatus(401);
    }

    $client->send('POST', LOGIN, ['email' => 'nobody@example.com', 'password' => 'any password at all'], ['HTTP_X_FORWARDED_FOR' => '192.0.2.99'])
        ->assertStatus(429);
});

it('AUTH-RATE-01: changing the case of the address does not get around the limit', function () {
    $client = spa($this)->csrf();

    foreach (range(1, 5) as $ignored) {
        $client->send('POST', LOGIN, ['email' => 'nobody@example.com', 'password' => 'any password at all']);
    }

    $client->send('POST', LOGIN, ['email' => 'NOBODY@example.com', 'password' => 'any password at all'])->assertStatus(429);
});

it('AUTH-RATE-01: limits per address and client, so others can still log in', function () {
    $user = User::factory()->create();
    $client = spa($this)->csrf();

    foreach (range(1, 6) as $ignored) {
        $client->send('POST', LOGIN, ['email' => 'nobody@example.com', 'password' => 'any password at all']);
    }

    $client->send('POST', LOGIN, ['email' => $user->email, 'password' => UserFactory::TEST_PASSWORD])->assertOk();
});
