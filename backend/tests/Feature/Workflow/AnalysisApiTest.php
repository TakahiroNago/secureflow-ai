<?php

use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Jobs\AnalyzeWorkflowJob;
use App\Models\Organization;
use App\Models\OrganizationSetting;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Tests\Support\FailingAuditWriter;

/*
| docs/api-design.md §3.3. What the scan does with the input is in tests/Feature/Security/InputScanApiTest.php.
*/

uses(DatabaseTransactions::class);

const ANALYSES = '/api/v1/analyses';

beforeEach(function () {
    Queue::fake();
    $this->org = Organization::factory()->create();
    $this->member = userIn($this->org->id);
});

it('accepts an analysis, queues it and says what the scan decided', function () {
    loggedIn($this, $this->member)->send('POST', ANALYSES, ['input' => '毎週の売上報告を作成してください。'])
        ->assertStatus(202)
        ->assertJsonPath('data.status', 'queued')
        ->assertJsonPath('data.workflow_id', null)
        ->assertJsonPath('data.scan.status', 'scanned')
        ->assertJsonPath('data.scan.decision', 'allow')
        ->assertJson(fn ($json) => $json->whereType('data.scan.limitations_notice', 'string')->etc());

    Queue::assertPushed(AnalyzeWorkflowJob::class);
    expect(DB::table('ai_analysis_requests')->value('input_char_count'))->toBe(17);
});

it('does not repeat the input in an error', function (array $body) {
    $response = loggedIn($this, $this->member)->send('POST', ANALYSES, $body)->assertStatus(422);

    expect($response->getContent())->not->toContain('marker-in-the-input');
})->with([
    'unknown field' => [['input' => 'marker-in-the-input', 'extra' => 'x']],
    'too long' => [['input' => 'marker-in-the-input'.str_repeat('あ', 4000)]],
]);

it('refuses what is not a usable input', function (array $body) {
    loggedIn($this, $this->member)->send('POST', ANALYSES, $body)
        ->assertStatus(422)
        ->assertJsonPath('code', 'VALIDATION_FAILED');

    Queue::assertNothingPushed();
})->with([
    'missing' => [[]],
    'empty' => [['input' => '']],
    'blank' => [['input' => '   ']],
    'a number' => [['input' => 5]],
    'an array' => [['input' => ['a']]],
]);

it('uses the organization\'s limit on the input length', function () {
    OrganizationSetting::query()->insert([
        'organization_id' => $this->org->id,
        'monthly_token_limit' => 1000,
        'user_daily_request_limit' => 10,
        'max_input_chars' => 5,
        'updated_at' => now(),
    ]);
    $client = loggedIn($this, $this->member);

    $client->send('POST', ANALYSES, ['input' => 'あいうえお'])->assertStatus(202);
    $client->send('POST', ANALYSES, ['input' => 'あいうえおか'])->assertStatus(422);
});

it('refuses an auditor, and anyone not logged in', function () {
    loggedIn($this, userIn($this->org->id, 'auditor'))->send('POST', ANALYSES, ['input' => 'x'])
        ->assertStatus(403)
        ->assertJsonPath('code', 'FORBIDDEN');

    spa($this)->csrf()->send('POST', ANALYSES, ['input' => 'x'])->assertStatus(401);

    Queue::assertNothingPushed();
});

it('answers 429 after 10 a minute, per user', function () {
    $client = loggedIn($this, $this->member);

    foreach (range(1, 10) as $ignored) {
        $client->send('POST', ANALYSES, ['input' => 'x'])->assertStatus(202);
    }

    $client->send('POST', ANALYSES, ['input' => 'x'])
        ->assertStatus(429)
        ->assertHeader('Retry-After')
        ->assertJsonPath('code', 'RATE_LIMITED');

    loggedIn($this, userIn($this->org->id), ip: '203.0.113.11')->send('POST', ANALYSES, ['input' => 'x'])->assertStatus(202);
});

it('answers 503 and queues nothing while the audit log cannot be written', function () {
    $client = loggedIn($this, $this->member);
    useAuditWriter(new FailingAuditWriter('53100', 'could not extend file: No space left on device'));

    // A login-free write that fails marks the audit as unavailable.
    app(AuditLogger::class)->recordAfterTransaction(
        AuditEntry::system(AuditEventType::AnalysisFailed, $this->member, 'failure'),
        'test',
    );

    $client->send('POST', ANALYSES, ['input' => 'x'])->assertStatus(503)->assertJsonPath('code', 'SERVICE_UNAVAILABLE');

    Queue::assertNothingPushed();
    expect(DB::table('ai_analysis_requests')->count())->toBe(0);
});

it('shows an analysis to the person who asked', function () {
    $client = loggedIn($this, $this->member);
    $id = $client->send('POST', ANALYSES, ['input' => 'x'])->json('data.id');

    $client->send('GET', ANALYSES.'/'.$id)
        ->assertOk()
        ->assertJsonPath('data.id', $id)
        ->assertJsonPath('data.status', 'queued')
        ->assertJsonMissingPath('data.input_masked')
        ->assertJsonMissingPath('data.input_char_count');
});

it('hides an analysis from everyone else, including an admin', function (Closure $other) {
    $id = loggedIn($this, $this->member)->send('POST', ANALYSES, ['input' => 'x'])->json('data.id');

    loggedIn($this, $other->call($this), ip: '203.0.113.12')->send('GET', ANALYSES.'/'.$id)
        ->assertStatus(404)
        ->assertJsonPath('code', 'NOT_FOUND');
})->with([
    'another member' => [fn () => userIn($this->org->id)],
    'an admin' => [fn () => userIn($this->org->id, 'admin')],
    'an auditor' => [fn () => userIn($this->org->id, 'auditor')],
    'an admin of another organization' => [fn () => userIn(Organization::factory()->create()->id, 'admin')],
]);
