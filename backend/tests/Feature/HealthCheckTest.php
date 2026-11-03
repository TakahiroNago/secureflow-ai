<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redis;

/*
| P0-HC-01 / P0-HC-02 (docs/test-strategy.md §12)
| Health responses must contain only {"status": ...} and never leak internals.
*/

// A closed local port gives an immediate "connection refused" (no DNS / network timeouts).
const UNREACHABLE_HOST = '127.0.0.1';
const UNREACHABLE_PORT = 1;

function breakDatabase(): void
{
    config([
        'database.connections.pgsql.host' => UNREACHABLE_HOST,
        'database.connections.pgsql.port' => UNREACHABLE_PORT,
    ]);
    DB::purge('pgsql');
}

function breakRedis(): void
{
    config([
        'database.redis.default.host' => UNREACHABLE_HOST,
        'database.redis.default.port' => UNREACHABLE_PORT,
        'database.redis.default.max_retries' => 0,
    ]);
    Redis::purge('default');
}

it('P0-HC-01: liveness returns only status ok', function () {
    $response = $this->getJson('/api/health/live');

    $response->assertOk()
        ->assertExactJson(['status' => 'ok'])
        ->assertHeaderMissing('X-Powered-By');
    expect($response->headers->get('Cache-Control'))->toContain('no-store');
});

it('P0-HC-01: liveness does not depend on database or redis', function () {
    breakDatabase();
    breakRedis();

    $this->getJson('/api/health/live')
        ->assertOk()
        ->assertExactJson(['status' => 'ok']);
});

it('P0-HC-02: readiness returns ok when database and redis are reachable', function () {
    $this->getJson('/api/health/ready')
        ->assertOk()
        ->assertExactJson(['status' => 'ok']);
});

it('P0-HC-02: readiness returns 503 without details when the database is unreachable', function () {
    breakDatabase();

    $response = $this->getJson('/api/health/ready');

    $response->assertStatus(503)->assertExactJson(['status' => 'unavailable']);
    expect($response->getContent())->not->toContain(UNREACHABLE_HOST)
        ->not->toContain('database')
        ->not->toContain('SQLSTATE');
});

it('P0-HC-02: readiness returns 503 without details when redis is unreachable', function () {
    breakRedis();

    $response = $this->getJson('/api/health/ready');

    $response->assertStatus(503)->assertExactJson(['status' => 'unavailable']);
    expect($response->getContent())->not->toContain(UNREACHABLE_HOST)
        ->not->toContain('redis');
});

it('does not emit CORS headers (same-origin only)', function () {
    $this->getJson('/api/health/live', ['Origin' => 'https://attacker.example'])
        ->assertHeaderMissing('Access-Control-Allow-Origin');

    $this->call('OPTIONS', '/api/health/live', server: [
        'HTTP_ORIGIN' => 'https://attacker.example',
        'HTTP_ACCESS_CONTROL_REQUEST_METHOD' => 'GET',
    ])->assertHeaderMissing('Access-Control-Allow-Origin');
});

it('does not expose the framework default /up health route', function () {
    $this->get('/up')->assertNotFound();
});
