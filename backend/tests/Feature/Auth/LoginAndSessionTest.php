<?php

use App\Models\Organization;
use App\Models\User;
use Database\Factories\UserFactory;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Process;

/*
| docs/api-design.md §3.1, docs/test-strategy.md §14 (AUTH-SES).
*/

uses(DatabaseTransactions::class);

// ---- Login -----------------------------------------------------------------------------------

it('logs in and returns only the documented fields', function () {
    $organization = Organization::factory()->create(['name' => 'Example Org']);
    $user = User::factory()->admin()->create(['organization_id' => $organization->id, 'name' => 'Example User', 'email' => 'user@example.com']);

    $response = spaLogin(spa($this), 'user@example.com');

    $response->assertOk()->assertExactJson(['data' => [
        'id' => $user->id,
        'name' => 'Example User',
        'email' => 'user@example.com',
        'role' => 'admin',
        'organization' => ['id' => $organization->id, 'name' => 'Example Org'],
    ]]);
    expect($response->getContent())->not->toContain('argon2')->not->toContain('password');
});

it('treats the address as case-insensitive', function () {
    User::factory()->create(['email' => 'user@example.com']);

    spaLogin(spa($this), 'USER@Example.COM')->assertOk();
});

it('returns the same user from auth/me', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);

    $client->send('GET', '/api/v1/auth/me')->assertOk()->assertJsonPath('data.id', $user->id);
});

it('rejects malformed input with 422 in RFC 9457 format', function (array $body, string $field) {
    $response = spa($this)->csrf()->send('POST', '/api/v1/auth/login', $body);

    $response->assertStatus(422)
        ->assertHeader('Content-Type', 'application/problem+json')
        ->assertJsonPath('code', 'VALIDATION_FAILED')
        ->assertJsonStructure(['type', 'title', 'status', 'code', 'detail', 'trace_id', 'errors' => [$field]]);
})->with([
    'no email' => [['password' => 'x'], 'email'],
    'no password' => [['email' => 'user@example.com'], 'password'],
    'not an address' => [['email' => 'not-an-address', 'password' => 'x'], 'email'],
    'address with NUL' => [['email' => "user\0@example.com", 'password' => 'x'], 'email'],
    'address not a string' => [['email' => ['a'], 'password' => 'x'], 'email'],
    'password not a string' => [['email' => 'user@example.com', 'password' => ['a']], 'password'],
    'password too long' => [['email' => 'user@example.com', 'password' => str_repeat('x', 1025)], 'password'],
    'unknown field' => [['email' => 'user@example.com', 'password' => 'x', 'role' => 'admin'], 'role'],
]);

it('does not echo submitted values in a validation error', function () {
    $response = spa($this)->csrf()->send('POST', '/api/v1/auth/login', ['email' => 'not-an-address', 'password' => 'my secret value', 'extra' => 'extra value']);

    expect($response->getContent())->not->toContain('my secret value')->not->toContain('extra value');
});

it('accepts a password with a NUL byte without a server error', function () {
    User::factory()->create(['email' => 'user@example.com']);

    spaLogin(spa($this), 'user@example.com', "abc\0def")->assertStatus(401);
});

it('requires JSON for a request body', function () {
    $client = spa($this)->csrf();

    $response = $this->call('POST', '/api/v1/auth/login', ['email' => 'user@example.com'], $client->cookies(), [], [
        'HTTP_ACCEPT' => 'application/json',
        'HTTP_ORIGIN' => 'http://localhost:8080',
        'HTTP_REFERER' => 'http://localhost:8080/',
        'HTTP_X_XSRF_TOKEN' => $client->cookies()['XSRF-TOKEN'],
        'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
    ], 'email=user%40example.com&password=x');

    $response->assertStatus(415)->assertJsonPath('code', 'UNSUPPORTED_MEDIA_TYPE');
});

it('writes nothing to the audit log, which is step 1-3', function () {
    $user = User::factory()->create();
    $before = DB::table('audit_logs')->count();

    $client = loggedIn($this, $user);
    spaLogin(spa($this), 'nobody@example.com', 'any password at all');
    $client->send('POST', '/api/v1/auth/logout')->assertNoContent();

    expect(DB::table('audit_logs')->count())->toBe($before);
});

// ---- Cookies ---------------------------------------------------------------------------------

it('sets the session cookie HttpOnly and SameSite=Lax, and the CSRF cookie readable by the SPA', function () {
    $response = spaLogin(spa($this), User::factory()->create()->email);

    $cookies = collect($response->baseResponse->headers->getCookies())->keyBy(fn ($cookie) => $cookie->getName());
    $session = $cookies[config('session.cookie')];

    expect($session->isHttpOnly())->toBeTrue()
        ->and(strtolower((string) $session->getSameSite()))->toBe('lax')
        ->and($cookies['XSRF-TOKEN']->isHttpOnly())->toBeFalse()
        ->and(strtolower((string) $cookies['XSRF-TOKEN']->getSameSite()))->toBe('lax');
});

it('marks cookies Secure when the application runs on HTTPS', function (string $url, string $expected) {
    $result = Process::path(base_path())->env(['APP_URL' => $url, 'SESSION_SECURE_COOKIE' => false])
        ->run(['php', '-r', 'chdir("'.base_path().'"); require "vendor/autoload.php"; $a = require "bootstrap/app.php"; $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap(); echo var_export(config("session.secure"), true);']);

    expect(trim($result->output()))->toBe($expected);
})->with([
    ['https://secureflow.example', 'true'],
    ['http://localhost:8080', 'false'],
]);

it('maps SESSION_IDLE_MINUTES and SESSION_ABSOLUTE_HOURS to their settings', function () {
    expect(config('session.lifetime'))->toBe(30)
        ->and(config('session.absolute_hours'))->toBe(12);

    $result = Process::path(base_path())->env(['SESSION_IDLE_MINUTES' => '7', 'SESSION_LIFETIME' => '999', 'SESSION_ABSOLUTE_HOURS' => '3'])
        ->run(['php', '-r', 'chdir("'.base_path().'"); require "vendor/autoload.php"; $a = require "bootstrap/app.php"; $a->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap(); echo config("session.lifetime"), "/", config("session.absolute_hours");']);

    expect(trim($result->output()))->toBe('7/3');
});

// ---- AUTH-SES-01: disabling ------------------------------------------------------------------

it('AUTH-SES-01: disabling a user ends their session at once, for good', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);

    $user->forceFill(['is_active' => false])->save();
    $client->send('GET', '/api/v1/auth/me')->assertStatus(401)->assertJsonPath('code', 'UNAUTHENTICATED');

    $user->forceFill(['is_active' => true])->save();
    $client->send('GET', '/api/v1/auth/me')->assertStatus(401);
});

// ---- AUTH-SES-02: limits ---------------------------------------------------------------------

it('AUTH-SES-02: stays valid while active, and expires after 30 idle minutes', function () {
    $client = loggedIn($this, User::factory()->create());

    $this->travel(29)->minutes();
    $client->send('GET', '/api/v1/auth/me')->assertOk();

    $this->travel(29)->minutes();
    $client->send('GET', '/api/v1/auth/me')->assertOk();

    $this->travel(31)->minutes();
    $client->send('GET', '/api/v1/auth/me')->assertStatus(401);
});

it('AUTH-SES-02: expires after 12 hours even with constant activity', function () {
    $client = loggedIn($this, User::factory()->create());

    // 11 hours 40 minutes of requests, one every 25 minutes.
    foreach (range(1, 28) as $ignored) {
        $this->travel(25)->minutes();
        $client->send('GET', '/api/v1/auth/me')->assertOk();
    }

    // Less than the idle limit since the last request, but past 12 hours since the login.
    $this->travel(21)->minutes();
    $client->send('GET', '/api/v1/auth/me')->assertStatus(401);
});

// ---- AUTH-SES-03: logout ---------------------------------------------------------------------

it('AUTH-SES-03: logout ends the session, and the old cookie stops working', function () {
    $client = loggedIn($this, User::factory()->create());
    $cookiesWhileLoggedIn = $client->cookies();
    $idWhileLoggedIn = decrypt($client->sessionCookie(), false);

    $client->send('POST', '/api/v1/auth/logout')->assertNoContent();

    expect(decrypt($client->sessionCookie(), false))->not->toBe($idWhileLoggedIn);

    $client->send('GET', '/api/v1/auth/me')->assertStatus(401);

    $replay = spa($this);
    $replay->useCookies($cookiesWhileLoggedIn);
    $replay->send('GET', '/api/v1/auth/me')->assertStatus(401);
});

it('AUTH-SES-03: logout replaces the CSRF token', function () {
    $client = loggedIn($this, User::factory()->create());
    $before = decrypt($client->cookies()['XSRF-TOKEN'], false);

    $client->send('POST', '/api/v1/auth/logout')->assertNoContent();

    expect(decrypt($client->cookies()['XSRF-TOKEN'], false))->not->toBe($before);
});

it('keeps sessions of different users apart', function () {
    $first = User::factory()->create();
    $second = User::factory()->create();
    $firstClient = loggedIn($this, $first, ip: '203.0.113.21');
    $secondClient = loggedIn($this, $second, ip: '203.0.113.22');

    $firstClient->send('GET', '/api/v1/auth/me')->assertJsonPath('data.id', $first->id);
    $secondClient->send('GET', '/api/v1/auth/me')->assertJsonPath('data.id', $second->id);

    $firstClient->send('POST', '/api/v1/auth/logout')->assertNoContent();
    $secondClient->send('GET', '/api/v1/auth/me')->assertOk();
});

it('accepts the role and is_active from the database, not from the session', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);

    $user->forceFill(['role' => 'auditor'])->save();

    $client->send('GET', '/api/v1/auth/me')->assertJsonPath('data.role', 'auditor');
});

it('keeps the factory password out of production paths', function () {
    expect(UserFactory::TEST_PASSWORD)->not->toBeEmpty();
    expect((string) file_get_contents(database_path('seeders/DatabaseSeeder.php')))->not->toContain('UserFactory')->not->toContain('User::');
});
