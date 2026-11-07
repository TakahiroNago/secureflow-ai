<?php

use App\Logging\RedactLogs;
use App\Logging\RedactSensitiveData;
use App\Models\Organization;
use App\Models\User;
use App\Support\Http\RequestId;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Monolog\Handler\TestHandler;
use Monolog\Logger as Monolog;
use Tests\Support\FakeSecrets;

/*
| ST-11, ST-29 and ST-32 (docs/test-strategy.md §29). The headers of nginx and what it answers by itself are in
| scripts/test-nginx-errors.sh.
*/

uses(DatabaseTransactions::class);

const HARDENING_ME = '/api/v1/auth/me';

/** A logger with the processor, as config/logging.php gives every channel. */
function redactingLogger(): array
{
    $handler = new TestHandler;
    $logger = new Monolog('test', [$handler]);
    $logger->pushProcessor(new RedactSensitiveData);

    return [$logger, $handler];
}

function logged(Closure $write): array
{
    [$logger, $handler] = redactingLogger();
    $write($logger);

    return $handler->getRecords()[0]->toArray();
}

beforeEach(function () {
    $this->org = Organization::factory()->create();
    $this->user = userIn($this->org->id);
});

// ---- ST-11: the limits ------------------------------------------------------------------------------

it('ST-11: stops a user at 60 a minute, with Retry-After and a record', function () {
    $client = loggedIn($this, $this->user);

    foreach (range(1, 60) as $ignored) {
        $client->send('GET', '/api/v1/workflows')->assertOk();
    }

    $client->send('GET', '/api/v1/workflows')->assertStatus(429)->assertJsonPath('code', 'RATE_LIMITED')->assertHeader('Retry-After');

    expect(DB::table('audit_logs')->where('event_type', 'rate_limit.exceeded')->where('organization_id', $this->org->id)->count())->toBe(1);
})->group('security');

it('ST-11: counts every route together, for each user on their own', function () {
    $client = loggedIn($this, $this->user);

    foreach (range(1, 30) as $ignored) {
        $client->send('GET', '/api/v1/workflows')->assertOk();
        $client->send('GET', '/api/v1/ai-usage/summary')->assertOk();
    }
    $client->send('GET', '/api/v1/dashboard/summary')->assertStatus(429);

    loggedIn($this, userIn($this->org->id))->send('GET', '/api/v1/workflows')->assertOk();
})->group('security');

it('ST-11: still lets the user see who they are, and log out', function () {
    $client = loggedIn($this, $this->user);

    foreach (range(1, 61) as $ignored) {
        $client->send('GET', '/api/v1/workflows');
    }

    $client->send('GET', HARDENING_ME)->assertOk();
    $client->send('POST', '/api/v1/auth/logout')->assertNoContent();
})->group('security');

it('ST-11: stops those with no session at 60 a minute, by address', function () {
    foreach (range(1, 60) as $ignored) {
        spa($this, ip: '203.0.113.77')->send('GET', HARDENING_ME)->assertStatus(401);
    }

    spa($this, ip: '203.0.113.77')->send('GET', HARDENING_ME)->assertStatus(429)->assertJsonPath('code', 'RATE_LIMITED')->assertHeader('Retry-After');
    spa($this, ip: '203.0.113.78')->send('GET', HARDENING_ME)->assertStatus(401);

    $client = loggedIn($this, $this->user, ip: '203.0.113.77');
    $client->send('GET', HARDENING_ME)->assertOk();
})->group('security');

it('ST-11: does not limit health', function () {
    foreach (range(1, 70) as $ignored) {
        $response = $this->getJson('/api/health/live');
    }

    $response->assertOk();
})->group('security');

// ---- Answers -----------------------------------------------------------------------------------------

it('keeps no answer in a cache', function (string $path, int $status) {
    $response = spa($this)->send('GET', $path)->assertStatus($status);

    expect($response->headers->get('Cache-Control'))->toContain('no-store');
})->with([[HARDENING_ME, 401], ['/api/health/live', 200], ['/api/v1/no-such-thing', 404]]);

it('keeps no logged-in answer in a cache either', function () {
    $response = loggedIn($this, $this->user)->send('GET', '/api/v1/workflows')->assertOk();

    expect($response->headers->get('Cache-Control'))->toContain('no-store');
});

it('ST-29: answers everything under the API in one format', function (string $method, string $path, int $status, string $code) {
    $response = spa($this)->send($method, $path)->assertStatus($status)->assertJsonPath('code', $code);

    expect($response->headers->get('Content-Type'))->toBe('application/problem+json')
        ->and(array_keys($response->json()))->toEqualCanonicalizing(['type', 'title', 'status', 'code', 'detail', 'trace_id']);
})->with([
    'no route in v1' => ['GET', '/api/v1/no-such-thing', 404, 'NOT_FOUND'],
    'no route under api' => ['GET', '/api/no-such-thing', 404, 'NOT_FOUND'],
    'a wrong method' => ['DELETE', '/api/v1/auth/login', 405, 'METHOD_NOT_ALLOWED'],
])->group('security');

it('ST-29: says nothing about what went wrong, and the id leads to the log', function () {
    $secret = FakeSecrets::apiKey('openai');
    Route::middleware('api')->get('/api/v1/test-exploding', fn () => throw new RuntimeException('SELECT secret FROM /var/www/html '.$secret));

    $response = $this->getJson('/api/v1/test-exploding')->assertStatus(500)->assertJsonPath('code', 'INTERNAL_ERROR');

    expect($response->getContent())->not->toContain($secret)
        ->not->toContain('/var/www')
        ->not->toContain('SELECT')
        ->not->toContain('RuntimeException')
        ->and($response->json('trace_id'))->toBe(app(RequestId::class)->value());
})->group('security');

it('leaves the format of health as it is', function () {
    $this->getJson('/api/health/live')->assertExactJson(['status' => 'ok']);
});

it('ST-29: does not send back the name of an unknown field that could be anything', function () {
    $secret = FakeSecrets::apiKey('github');
    $client = loggedIn($this, $this->user);

    $response = $client->send('POST', '/api/v1/analyses', ['input' => '報告', $secret => 'x'])->assertStatus(422);

    expect($response->getContent())->not->toContain($secret)
        ->and($response->json('errors'))->toHaveKey('unknown_field');

    $client->send('POST', '/api/v1/analyses', ['input' => '報告', 'made_up' => 'x'])->assertStatus(422)->assertJsonValidationErrors(['made_up']);
})->group('security');

// ---- ST-32 -------------------------------------------------------------------------------------------

$sql = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    '" OR ""="',
    "1' UNION SELECT password FROM users --",
    '\\\'; SELECT pg_sleep(5); --',
];

it('ST-32: a login takes it as a wrong password', function (string $attack) {
    $client = spa($this);
    $client->csrf();

    $client->send('POST', '/api/v1/auth/login', ['email' => $this->user->email, 'password' => $attack])->assertStatus(401)->assertJsonPath('code', 'AUTH_FAILED');

    expect(DB::table('users')->where('id', $this->user->id)->exists())->toBeTrue();
})->with($sql)->group('security');

it('ST-32: a login refuses it as an address, and finds nobody', function (string $attack) {
    $client = spa($this);
    $client->csrf();

    expect($client->send('POST', '/api/v1/auth/login', ['email' => $attack, 'password' => 'x'])->status())->toBeIn([401, 422]);
})->with($sql)->group('security');

it('ST-32: filters refuse it', function (string $attack) {
    $admin = loggedIn($this, userIn($this->org->id, 'admin'));
    $query = rawurlencode($attack);

    foreach (['/api/v1/workflows?status=', '/api/v1/audit-logs?event_type=', '/api/v1/audit-logs?actor_user_id=', '/api/v1/audit-logs?from=', '/api/v1/ai-usage/summary?period='] as $path) {
        $admin->send('GET', $path.$query)->assertStatus(422);
    }
})->with($sql)->group('security');

it('ST-32: an id in a path is only ever not found', function (string $attack) {
    loggedIn($this, $this->user)->send('GET', '/api/v1/workflows/'.rawurlencode($attack))->assertStatus(404)->assertJsonPath('code', 'NOT_FOUND');
})->with($sql)->group('security');

it('ST-32: text is kept as text, or stopped, and changes nothing else', function (string $attack) {
    $users = DB::table('users')->count();
    $client = loggedIn($this, $this->user);

    expect($client->send('POST', '/api/v1/security/scan-preview', ['input' => $attack])->status())->toBe(200);

    expect(DB::table('users')->count())->toBe($users);
})->with($sql)->group('security');

// ---- ST-29: the logs ---------------------------------------------------------------------------------

it('ST-29: masks personal data in a message and in the context', function () {
    $record = logged(fn ($log) => $log->warning('宛先 a@example.com', ['to' => ['b@example.com'], 'count' => 2]));

    expect($record['message'])->toBe('宛先 [EMAIL_REDACTED]')
        ->and($record['context']['to'][0])->toBe('[EMAIL_REDACTED]')
        ->and($record['context']['count'])->toBe(2);
})->group('security');

it('ST-29: takes the whole string with a secret', function () {
    $secret = FakeSecrets::apiKey('openai');
    $record = logged(fn ($log) => $log->error('キーは '.$secret.' です', ['deep' => ['deeper' => ['Authorization: '.$secret]]]));

    expect($record['message'])->toBe(RedactSensitiveData::REDACTED)
        ->and($record['context']['deep']['deeper'][0])->toBe(RedactSensitiveData::REDACTED)
        ->and(json_encode($record))->not->toContain($secret);
})->group('security');

it('ST-29: keeps an exception by its class and place, not its message', function () {
    $record = logged(fn ($log) => $log->error('failed', ['exception' => new RuntimeException('SELECT * FROM users WHERE name = 山田太郎', 0, new LogicException('inner 佐藤'))]));

    expect($record['context']['exception']['class'])->toBe(RuntimeException::class)
        ->and($record['context']['exception']['previous'])->toBe(LogicException::class)
        ->and($record['context']['exception']['file'])->toContain('ApiHardeningTest')
        ->and($record['context']['exception']['line'])->toBeInt()
        ->and(json_encode($record, JSON_UNESCAPED_UNICODE))->not->toContain('山田太郎')
        ->and(json_encode($record, JSON_UNESCAPED_UNICODE))->not->toContain('佐藤');
})->group('security');

it('ST-29: does not write out an object', function () {
    $user = new User;
    $user->forceFill(['email' => 'x@example.com', 'password' => 'a password']);

    $record = logged(fn ($log) => $log->info('who', ['user' => $user]));

    expect($record['context']['user'])->toBe('['.User::class.']');
})->group('security');

it('ST-29: leaves what identifies a failure alone', function () {
    $id = '019a0000-0000-7000-8000-00000000000a';
    $record = logged(fn ($log) => $log->critical('audit.write_failed', ['metric' => 'audit.write_failed', 'request_id' => $id, 'sqlstate' => '53100', 'first_broken_seq' => 3, 'failed' => true, 'none' => null]));

    expect($record['message'])->toBe('audit.write_failed')
        ->and($record['context'])->toBe(['metric' => 'audit.write_failed', 'request_id' => $id, 'sqlstate' => '53100', 'first_broken_seq' => 3, 'failed' => true, 'none' => null]);
})->group('security');

it('ST-29: redacts a line it cannot check, and cuts one that is too long', function () {
    $record = logged(fn ($log) => $log->info(str_repeat('あ', 5000)));

    expect(mb_strlen($record['message']))->toBe(4001);

    $record = logged(fn ($log) => $log->info('bad', ['text' => "\xB1\x31"]));

    expect($record['context']['text'])->toBeString();
})->group('security');

it('ST-29: stops at a depth it can check, and keeps what is above it', function () {
    $deep = 'bottom';
    foreach (range(1, 10) as $_) {
        $deep = ['next' => $deep];
    }
    $record = logged(fn ($log) => $log->info('x', ['deep' => $deep, 'shallow' => ['a' => ['b' => 'kept']]]));

    expect(json_encode($record['context']))->not->toContain('bottom')->toContain('[REDACTED]')
        ->and($record['context']['shallow'])->toBe(['a' => ['b' => 'kept']]);
})->group('security');

it('ST-29: gives each line the id of the request', function () {
    $record = logged(fn ($log) => $log->info('x'));

    expect($record['extra']['trace_id'])->toBe(app(RequestId::class)->value());
})->group('security');

it('ST-29: every channel that writes has it', function (string $channel) {
    expect(config("logging.channels.{$channel}.tap"))->toContain(RedactLogs::class);
})->with(['single', 'daily', 'stderr', 'syslog', 'errorlog', 'slack', 'papertrail'])->group('security');

it('ST-29: a channel really runs it', function () {
    $logger = app('log')->channel('stderr');

    expect(collect($logger->getLogger()->getProcessors())->contains(fn ($processor) => $processor instanceof RedactSensitiveData))->toBeTrue();
})->group('security');
