<?php

use App\Domain\Auth\CommonPasswordList;
use App\Models\Organization;
use App\Models\User;
use Database\Factories\UserFactory;
use Database\Seeders\DatabaseSeeder;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Symfony\Component\Console\Exception\InvalidOptionException;
use Tests\Support\SpaClient;
use Tests\TestCase;

/*
| docs/api-design.md §3.1.2, docs/test-strategy.md §14 (AUTH-PW, AUTH-HASH, AUTH-CMD, AUTH-SEED).
*/

uses(DatabaseTransactions::class);

const PASSWORD_URI = '/api/v1/account/password';
const NEW_PASSWORD = 'a much longer new passphrase';

function changePassword(SpaClient $client, string $new = NEW_PASSWORD, string $current = UserFactory::TEST_PASSWORD): TestResponse
{
    return $client->send('PATCH', PASSWORD_URI, ['current_password' => $current, 'new_password' => $new], ['HTTP_IDEMPOTENCY_KEY' => (string) Str::uuid7()]);
}

// ---- AUTH-PW-01 ------------------------------------------------------------------------------

it('AUTH-PW-01: other sessions stop working and the current one keeps working', function () {
    $user = User::factory()->create();
    $current = loggedIn($this, $user, ip: '203.0.113.31');
    $other = loggedIn($this, $user, ip: '203.0.113.32');
    $other->send('GET', '/api/v1/auth/me')->assertOk();

    changePassword($current)->assertOk()->assertJsonStructure(['data' => ['password_changed_at']]);

    $current->send('GET', '/api/v1/auth/me')->assertOk();
    $other->send('GET', '/api/v1/auth/me')->assertStatus(401);
    expect($user->fresh()->password_changed_at)->not->toBeNull();
});

it('AUTH-PW-01: a session that never made another request is also invalidated', function () {
    $user = User::factory()->create();
    $idleOther = loggedIn($this, $user, ip: '203.0.113.33');
    $current = loggedIn($this, $user, ip: '203.0.113.34');

    changePassword($current)->assertOk();

    $idleOther->send('GET', '/api/v1/auth/me')->assertStatus(401);
});

it('AUTH-PW-01: the session ID changes, and the old ID stops working', function () {
    $current = loggedIn($this, User::factory()->create());
    $cookiesBefore = $current->cookies();

    changePassword($current)->assertOk();

    expect(decrypt($current->sessionCookie(), false))->not->toBe(decrypt($cookiesBefore[config('session.cookie')], false));

    $replay = spa($this);
    $replay->useCookies($cookiesBefore);
    $replay->send('GET', '/api/v1/auth/me')->assertStatus(401);
});

it('AUTH-PW-01: only the new password logs in afterwards', function () {
    $user = User::factory()->create();
    changePassword(loggedIn($this, $user))->assertOk();

    spaLogin(spa($this, ip: '203.0.113.35'), $user->email)->assertStatus(401);
    spaLogin(spa($this, ip: '203.0.113.36'), $user->email, NEW_PASSWORD)->assertOk();
});

it('AUTH-PW-01: changing the password does not extend the absolute session limit', function () {
    $client = loggedIn($this, User::factory()->create());

    foreach (range(1, 28) as $step) {
        $this->travel(25)->minutes();
        if ($step === 27) {
            changePassword($client)->assertOk();
        } else {
            $client->send('GET', '/api/v1/auth/me')->assertOk();
        }
    }

    $this->travel(21)->minutes();
    $client->send('GET', '/api/v1/auth/me')->assertStatus(401);
});

it('AUTH-PW-01: uses the new password exactly as typed, including surrounding spaces', function () {
    $user = User::factory()->create();

    changePassword(loggedIn($this, $user), '  spaces around this one  ')->assertOk();

    expect(Hash::check('  spaces around this one  ', $user->fresh()->password))->toBeTrue()
        ->and(Hash::check('spaces around this one', $user->fresh()->password))->toBeFalse();
});

// ---- AUTH-PW-02 ------------------------------------------------------------------------------

it('AUTH-PW-02: a wrong current password is refused and does not count towards the lock', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);

    changePassword($client, current: 'not the current password')
        ->assertStatus(422)
        ->assertJsonPath('code', 'CURRENT_PASSWORD_INVALID');

    $fresh = $user->fresh();
    expect($fresh->failed_login_count)->toBe(0)
        ->and(Hash::check(UserFactory::TEST_PASSWORD, $fresh->password))->toBeTrue();
});

it('AUTH-PW-02: refuses a new password that breaks the policy', function (string $new) {
    $user = User::factory()->create();

    changePassword(loggedIn($this, $user), $new)
        ->assertStatus(422)
        ->assertJsonPath('code', 'VALIDATION_FAILED')
        ->assertJsonStructure(['errors' => ['new_password']]);

    expect(Hash::check(UserFactory::TEST_PASSWORD, $user->fresh()->password))->toBeTrue();
})->with([
    '11 characters' => ['abcdefghijk'],
    'too long' => [str_repeat('x', 1025)],
    'on the list' => ['passwordpassword'],
    'on the list, other case' => ['PassWordPASSWORD'],
    'same as current' => [UserFactory::TEST_PASSWORD],
]);

it('AUTH-PW-02: accepts 12 characters and the maximum length', function (string $new) {
    changePassword(loggedIn($this, User::factory()->create()), $new)->assertOk();
})->with([
    '12 characters' => ['zx9!qv7#mk2$'],
    'maximum length' => [str_repeat('zx9!', 256)],
]);

it('AUTH-PW-02: refuses unknown fields and limits attempts', function () {
    $client = loggedIn($this, User::factory()->create());

    $client->send('PATCH', PASSWORD_URI, ['current_password' => 'x', 'new_password' => NEW_PASSWORD, 'role' => 'admin'], ['HTTP_IDEMPOTENCY_KEY' => (string) Str::uuid7()])
        ->assertStatus(422)
        ->assertJsonStructure(['errors' => ['role']]);

    foreach (range(1, 4) as $ignored) {
        changePassword($client, current: 'not the current password')->assertStatus(422);
    }

    changePassword($client, current: 'not the current password')->assertStatus(429)->assertHeader('Retry-After');
});

// ---- AUTH-PW-03: the list --------------------------------------------------------------------

it('AUTH-PW-03: the bundled list matches the documented checksum', function () {
    $hash = hash_file('sha256', CommonPasswordList::path());
    $design = (string) file_get_contents(base_path('resources/security/common-passwords.NOTICE.md'));

    expect($hash)->toBe(CommonPasswordList::SHA256)
        ->and($design)->toContain($hash);
});

it('AUTH-PW-03: the attribution stays in place', function () {
    $notice = (string) file_get_contents(base_path('resources/security/common-passwords.NOTICE.md'));

    expect($notice)
        ->toContain('Mark Burnett')
        ->toContain('35d74839e66f44d116e694369d86a5bf07aaed6f')
        ->toContain('424a3e03a17df0a2bc2b3ca749d81b04e79d59cb7aeec8876a5a3f308d0caf51')
        ->toContain('MIT License')
        ->toContain('Copyright (c) 2018 Daniel Miessler');
});

it('AUTH-PW-03: the list has the documented shape', function () {
    $entries = file(CommonPasswordList::path(), FILE_IGNORE_NEW_LINES);

    expect($entries)->toHaveCount(46045);

    foreach ($entries as $entry) {
        expect(strlen($entry))->toBeGreaterThanOrEqual(12);
        if (str_contains($entry, '@') || $entry !== strtolower($entry)) {
            $this->fail('An entry breaks the documented processing.');
        }
    }
});

it('AUTH-PW-03: checking a password makes no network request', function () {
    Http::preventStrayRequests();

    expect(CommonPasswordList::contains('passwordpassword'))->toBeTrue()
        ->and(CommonPasswordList::contains('PASSWORDPASSWORD'))->toBeTrue()
        ->and(CommonPasswordList::contains('an entry that is not listed anywhere'))->toBeFalse();
});

// ---- AUTH-HASH-01 ----------------------------------------------------------------------------

it('AUTH-HASH-01: stores Argon2id', function () {
    $user = User::factory()->create();

    expect(password_get_info($user->password)['algoName'])->toBe('argon2id');

    changePassword(loggedIn($this, $user))->assertOk();

    expect(password_get_info($user->fresh()->password)['algoName'])->toBe('argon2id');
});

it('AUTH-HASH-01: uses a production cost that meets the OWASP minimum', function () {
    $config = require config_path('hashing.php');

    expect($config['driver'])->toBe('argon2id')
        ->and((int) env('ARGON_MEMORY'))->toBe(1024); // tests only, set by phpunit.xml

    $source = (string) file_get_contents(config_path('hashing.php'));
    expect($source)->toContain("env('ARGON_MEMORY', 65536)")
        ->toContain("env('ARGON_TIME', 4)");
});

it('AUTH-HASH-01: does not keep the password hash in the session', function () {
    $user = User::factory()->create();
    $client = loggedIn($this, $user);
    $client->send('GET', '/api/v1/auth/me')->assertOk();

    $session = serialize(app('session')->driver()->all());

    expect($session)->toContain('password_fingerprint')
        ->not->toContain($user->password)
        ->not->toContain('argon2id');
});

it('AUTH-HASH-01: does not write passwords or hashes to the log', function () {
    $user = User::factory()->create();
    $logged = [];
    Event::listen(MessageLogged::class, function (MessageLogged $event) use (&$logged) {
        $logged[] = $event->message.json_encode($event->context);
    });

    $client = loggedIn($this, $user);
    spaLogin(spa($this, ip: '203.0.113.40'), $user->email, 'a wrong password value');
    changePassword($client, 'x')->assertStatus(422);
    changePassword($client)->assertOk();

    $output = implode("\n", $logged);
    expect($output)->not->toContain(UserFactory::TEST_PASSWORD)
        ->not->toContain('a wrong password value')
        ->not->toContain(NEW_PASSWORD)
        ->not->toContain('argon2id');
});

it('AUTH-HASH-01: logs a failed query without its bindings', function () {
    $logged = [];
    Event::listen(MessageLogged::class, function (MessageLogged $event) use (&$logged) {
        $logged[] = $event->message.json_encode($event->context);
    });

    report(new QueryException('pgsql', 'update users set password = ?', ['$argon2id$secret-binding'], new Exception('failure')));

    $output = implode("\n", $logged);
    expect($output)->toContain('Database query failed.')
        ->not->toContain('secret-binding')
        ->not->toContain('update users');
});

it('AUTH-HASH-01: keeps function arguments out of stack traces', function () {
    $trace = (fn (string $secret) => (new Exception)->getTraceAsString())('a-secret-argument');

    expect(ini_get('zend.exception_ignore_args'))->toBe('1')
        ->and($trace)->not->toContain('a-secret-argument');
});

// ---- Models -----------------------------------------------------------------------------------

it('generates UUIDv7 keys', function () {
    $organization = Organization::factory()->create();
    $user = User::factory()->create(['organization_id' => $organization->id]);

    foreach ([$organization->id, $user->id] as $id) {
        expect(Str::isUuid($id))->toBeTrue()
            ->and(appDb()->selectOne('SELECT uuid_extract_version(?::uuid) AS v', [$id])->v)->toBe(7);
    }
});

it('does not allow privilege fields to be mass assigned', function () {
    $user = new User(['role' => 'admin', 'is_active' => false, 'organization_id' => 'x', 'locked_until' => now(), 'failed_login_count' => 9]);

    expect($user->getAttributes())->toBe([]);
});

it('hides the password from serialization', function () {
    expect(User::factory()->create()->toArray())->not->toHaveKey('password');
});

it('has no remember token', function () {
    expect(User::factory()->make()->getRememberTokenName())->toBe('');
});

it('reads settings through the organization', function () {
    $organization = Organization::factory()->create();
    $organization->settings()->create(['monthly_token_limit' => 5, 'user_daily_request_limit' => 2]);

    expect($organization->fresh()->settings->monthly_token_limit)->toBe(5)
        ->and($organization->fresh()->settings->max_input_chars)->toBe(4000);
});

// ---- AUTH-CMD-01 -----------------------------------------------------------------------------

function createUserCommand(TestCase $test, array $options, ?string $password = NEW_PASSWORD, ?string $again = null)
{
    $command = $test->artisan('user:create', $options);

    return $password === null ? $command : $command
        ->expectsQuestion('Password', $password)
        ->expectsQuestion('Password (again)', $again ?? $password);
}

it('AUTH-CMD-01: creates a user who can log in, without printing the password', function () {
    $organization = Organization::factory()->create(['name' => 'Example Org']);

    createUserCommand($this, ['--organization' => 'Example Org', '--name' => 'New User', '--email' => 'new@example.com', '--role' => 'admin'])
        ->doesntExpectOutputToContain(NEW_PASSWORD)
        ->assertExitCode(0);

    $user = User::query()->where('email', 'new@example.com')->firstOrFail();

    expect($user->role)->toBe('admin')
        ->and($user->organization_id)->toBe($organization->id)
        ->and($user->password_changed_at)->not->toBeNull()
        ->and(password_get_info($user->password)['algoName'])->toBe('argon2id');

    spaLogin(spa($this), 'new@example.com', NEW_PASSWORD)->assertOk();
});

it('AUTH-CMD-01: finds the organization by ID', function () {
    $organization = Organization::factory()->create();

    createUserCommand($this, ['--organization' => $organization->id, '--name' => 'New User', '--email' => 'new@example.com'])
        ->assertExitCode(0);

    expect(User::query()->where('email', 'new@example.com')->value('role'))->toBe('member');
});

it('AUTH-CMD-01: has no option that accepts a password', function () {
    expect(fn () => Artisan::call('user:create', ['--password' => 'x']))->toThrow(InvalidOptionException::class);
});

it('AUTH-CMD-01: refuses bad input and creates nothing', function (array $options, string $password) {
    Organization::factory()->create(['name' => 'Example Org']);
    User::factory()->create(['email' => 'taken@example.com']);
    $before = User::query()->count();

    createUserCommand($this, [
        '--organization' => 'Example Org', '--name' => 'New User', '--email' => 'new@example.com', ...$options,
    ], $password)->assertExitCode(1);

    expect(User::query()->count())->toBe($before);
})->with([
    'short password' => [[], 'abcdefghijk'],
    'common password' => [[], 'passwordpassword'],
    'invalid role' => [['--role' => 'root'], NEW_PASSWORD],
    'invalid email' => [['--email' => 'nope'], NEW_PASSWORD],
    'duplicate email' => [['--email' => 'taken@example.com'], NEW_PASSWORD],
    'duplicate email, other case' => [['--email' => 'TAKEN@example.com'], NEW_PASSWORD],
    'no name' => [['--name' => ''], NEW_PASSWORD],
]);

it('AUTH-CMD-01: refuses passwords that do not match', function () {
    Organization::factory()->create(['name' => 'Example Org']);

    createUserCommand($this, ['--organization' => 'Example Org', '--name' => 'New User', '--email' => 'new@example.com'], NEW_PASSWORD, 'something else entirely')
        ->assertExitCode(1);

    expect(User::query()->where('email', 'new@example.com')->exists())->toBeFalse();
});

it('AUTH-CMD-01: refuses an unknown or ambiguous organization before asking for a password', function () {
    Organization::factory()->count(2)->create(['name' => 'Same Name']);

    createUserCommand($this, ['--organization' => 'Same Name', '--name' => 'x', '--email' => 'a@example.com'], null)->assertExitCode(1);
    createUserCommand($this, ['--organization' => 'Missing', '--name' => 'x', '--email' => 'b@example.com'], null)->assertExitCode(1);
});

// ---- AUTH-SEED-01 ----------------------------------------------------------------------------

it('AUTH-SEED-01: seeds only an organization and its settings, and can run again', function () {
    $users = User::query()->count();

    $this->seed(DatabaseSeeder::class);
    $this->seed(DatabaseSeeder::class);

    $organizations = Organization::query()->where('name', 'Default Organization')->get();

    expect(User::query()->count())->toBe($users)
        ->and($organizations)->toHaveCount(1)
        ->and($organizations->first()->settings)->not->toBeNull();
});
