<?php

use App\Console\Commands\SelfTestRecoverCommand;
use App\Jobs\RunSecuritySelfTestJob;
use App\Models\Organization;
use App\Models\SecurityTestRun;
use App\SelfTest\CaseOutcome;
use App\SelfTest\ClosureCase;
use App\SelfTest\SelfTestRuns;
use App\Support\Organization\OrganizationContext;
use Carbon\CarbonInterface;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Str;
use Tests\Support\FailingAuditWriter;

/*
| docs/api-design.md §3.7 (step 3-3). ST-06 over the runs, the life of a run from 202 to its results, one at a time
| per organization, the audit records, the dashboard, and what a dead worker leaves behind.
*/

uses(DatabaseTransactions::class);

const TEST_RUNS_URI = '/api/v1/security/test-runs';

function selfTestEvents(string $organizationId, string $type): array
{
    return DB::table('audit_logs')->where('organization_id', $organizationId)->where('event_type', $type)->orderBy('chain_seq')->get()->all();
}

function processRun(string $runId, string $organizationId): void
{
    (new RunSecuritySelfTestJob($runId, $organizationId))->handle(app(SelfTestRuns::class), app(OrganizationContext::class));
}

function runRow(string $id): ?object
{
    return DB::table('security_test_runs')->where('id', $id)->first();
}

beforeEach(function () {
    Queue::fake();
    $this->org = Organization::factory()->create();
    $this->admin = userIn($this->org->id, 'admin');
    $this->auditor = userIn($this->org->id, 'auditor');
    $this->member = userIn($this->org->id);
});

it('ST-06: an admin starts a run, and everyone in the organization reads the runs', function (string $role, int $startStatus) {
    $user = match ($role) {
        'admin' => $this->admin,
        'auditor' => $this->auditor,
        'member' => $this->member,
    };
    $client = loggedIn($this, $user);

    $client->send('POST', TEST_RUNS_URI)->assertStatus($startStatus);
    $client->send('GET', TEST_RUNS_URI)->assertOk();

    if ($startStatus === 202) {
        $id = SecurityTestRun::query()->withoutGlobalScopes()->where('organization_id', $this->org->id)->value('id');
        $client->send('GET', TEST_RUNS_URI.'/'.$id)->assertOk();
        loggedIn($this, $this->member)->send('GET', TEST_RUNS_URI.'/'.$id)->assertOk();
    } else {
        expect(DB::table('security_test_runs')->where('organization_id', $this->org->id)->count())->toBe(0);
    }
})->with([['admin', 202], ['auditor', 403], ['member', 403]])->group('security');

it('starts a run: queued, recorded in the chain, and the job on its own queue', function () {
    $response = loggedIn($this, $this->admin)->send('POST', TEST_RUNS_URI)->assertStatus(202);

    // Identical, not equal: a null count (the instance before the row was read back) must not pass as 0.
    expect($response->json('data.status'))->toBe('queued')
        ->and([$response->json('data.total'), $response->json('data.passed'), $response->json('data.failed')])->toBe([0, 0, 0])
        ->and($response->json('data.finished_at'))->toBeNull()
        ->and($response->json('data.created_at'))->toBeString()
        ->and($response->json('data.triggered_by'))->toBe(['id' => $this->admin->id, 'name' => $this->admin->name])
        ->and($response->json('data'))->not->toHaveKey('results');

    $id = $response->json('data.id');
    Queue::assertPushed(RunSecuritySelfTestJob::class, fn (RunSecuritySelfTestJob $job) => $job->runId === $id && $job->organizationId === $this->org->id && $job->queue === 'selftest');

    $events = selfTestEvents($this->org->id, 'selftest.started');
    expect($events)->toHaveCount(1)
        ->and($events[0]->actor_user_id)->toBe($this->admin->id)
        ->and($events[0]->resource_type)->toBe('security_test_run')
        ->and($events[0]->resource_id)->toBe($id);
});

it('runs one at a time per organization: a second start is 409 while one is queued or running', function () {
    $client = loggedIn($this, $this->admin);
    $first = $client->send('POST', TEST_RUNS_URI)->assertStatus(202)->json('data.id');

    $client->send('POST', TEST_RUNS_URI)->assertStatus(409)->assertJsonPath('code', 'SELF_TEST_RUNNING');
    appDb()->table('security_test_runs')->where('id', $first)->update(['status' => 'running']);
    $client->send('POST', TEST_RUNS_URI)->assertStatus(409)->assertJsonPath('code', 'SELF_TEST_RUNNING');

    // Another organization is not held up by this one.
    $otherAdmin = userIn(Organization::factory()->create()->id, 'admin');
    loggedIn($this, $otherAdmin)->send('POST', TEST_RUNS_URI)->assertStatus(202);

    expect(DB::table('security_test_runs')->where('organization_id', $this->org->id)->count())->toBe(1)
        ->and(selfTestEvents($this->org->id, 'selftest.started'))->toHaveCount(1);
});

it('refuses a fourth start within an hour, per organization', function () {
    $client = loggedIn($this, $this->admin);

    $client->send('POST', TEST_RUNS_URI)->assertStatus(202);
    $client->send('POST', TEST_RUNS_URI)->assertStatus(409);
    $client->send('POST', TEST_RUNS_URI)->assertStatus(409);
    $client->send('POST', TEST_RUNS_URI)->assertStatus(429)->assertHeader('Retry-After');
});

it('answers 503 and starts nothing when the record cannot be written', function () {
    $client = loggedIn($this, $this->admin);
    useAuditWriter(new FailingAuditWriter('53100', 'could not extend file: No space left on device'));

    $client->send('POST', TEST_RUNS_URI)->assertStatus(503)->assertJsonPath('code', 'SERVICE_UNAVAILABLE');

    expect(DB::table('security_test_runs')->where('organization_id', $this->org->id)->count())->toBe(0);
    Queue::assertNothingPushed();
});

it('processes a run to completion: every case passes, the results are shown, and the chain has the completion', function () {
    $client = loggedIn($this, $this->admin);
    $id = $client->send('POST', TEST_RUNS_URI)->assertStatus(202)->json('data.id');

    processRun($id, $this->org->id);

    $row = runRow($id);
    expect($row->status)->toBe('completed')
        ->and((int) $row->total)->toBe(26)
        ->and((int) $row->passed)->toBe(26)
        ->and((int) $row->failed)->toBe(0)
        ->and($row->ruleset_version)->toMatch('/^\d{4}\.\d+\.\d+\//')
        ->and($row->policy_version)->toBe('2026.11.1')
        ->and($row->started_at)->not->toBeNull()
        ->and($row->finished_at)->not->toBeNull();

    $events = selfTestEvents($this->org->id, 'selftest.completed');
    expect($events)->toHaveCount(1)
        ->and($events[0]->actor_type)->toBe('system')
        ->and($events[0]->result)->toBe('success')
        ->and(json_decode($events[0]->metadata, true))->toEqualCanonicalizing(['total' => 26, 'passed' => 26, 'failed' => 0, 'status' => 'completed']);

    $shown = loggedIn($this, $this->member)->send('GET', TEST_RUNS_URI.'/'.$id)->assertOk()->json('data');
    expect($shown['status'])->toBe('completed')
        ->and($shown['results'])->toHaveCount(26)
        ->and($shown['results'][0])->toMatchArray(['case_id' => 'ST-01', 'category' => 'workflow', 'passed' => true])
        ->and(array_keys($shown['results'][0]))->toEqualCanonicalizing(['case_id', 'category', 'name', 'expected', 'actual', 'passed', 'duration_ms', 'details'])
        ->and(collect($shown['results'])->every(fn (array $r) => $r['passed'] === true))->toBeTrue()
        ->and(array_column($shown['ci_only_cases'], 'case_id'))->toContain('ST-05', 'ST-34')
        ->and(count($shown['ci_only_cases']))->toBe(13);

    // The list is newest first and carries no results.
    $list = $client->send('GET', TEST_RUNS_URI)->assertOk()->json('data');
    expect($list[0]['id'])->toBe($id)
        ->and($list[0])->not->toHaveKey('results');

    // And the dashboard shows it to a member too.
    $summary = loggedIn($this, $this->member)->send('GET', '/api/v1/dashboard/summary')->assertOk()->json('data.self_test');
    expect($summary['latest'])->toMatchArray(['id' => $id, 'status' => 'completed', 'total' => 26, 'passed' => 26, 'failed' => 0])
        ->and($summary['latest']['finished_at'])->not->toBeNull();

    // A new run may start now.
    $client->send('POST', TEST_RUNS_URI)->assertStatus(202);
});

it('does nothing when the job comes back: a second run of the job cannot repeat the work', function () {
    $id = loggedIn($this, $this->admin)->send('POST', TEST_RUNS_URI)->assertStatus(202)->json('data.id');

    processRun($id, $this->org->id);
    $finished = runRow($id)->finished_at;
    processRun($id, $this->org->id);

    expect(runRow($id)->finished_at)->toBe($finished)
        ->and(DB::table('security_test_results')->where('run_id', $id)->count())->toBe(26)
        ->and(selfTestEvents($this->org->id, 'selftest.completed'))->toHaveCount(1);
});

it('completes a run with a failed case, and records the completion as a failure', function () {
    $id = loggedIn($this, $this->admin)->send('POST', TEST_RUNS_URI)->assertStatus(202)->json('data.id');
    $cases = [new ClosureCase('ST-99', 'workflow', 'a check that fails', 'ok', fn () => CaseOutcome::of(false, 'failed: check'))];

    app(OrganizationContext::class)->run($this->org->id, fn () => app(SelfTestRuns::class)->process($id, $cases));

    $row = runRow($id);
    expect($row->status)->toBe('completed')
        ->and($row->error_code)->toBeNull()
        ->and([(int) $row->total, (int) $row->passed, (int) $row->failed])->toBe([1, 0, 1]);

    $events = selfTestEvents($this->org->id, 'selftest.completed');
    expect($events)->toHaveCount(1)
        ->and($events[0]->result)->toBe('failure')
        ->and(json_decode($events[0]->metadata, true))->toEqualCanonicalizing(['total' => 1, 'passed' => 0, 'failed' => 1, 'status' => 'completed']);
});

it('fails the run when the admin who started it was deactivated, and when the job fails', function () {
    $client = loggedIn($this, $this->admin);
    $id = $client->send('POST', TEST_RUNS_URI)->assertStatus(202)->json('data.id');
    appDb()->table('users')->where('id', $this->admin->id)->update(['is_active' => false]);

    processRun($id, $this->org->id);
    $row = runRow($id);
    expect($row->status)->toBe('failed')
        ->and($row->error_code)->toBe('SELF_TEST_FAILED');

    $events = selfTestEvents($this->org->id, 'selftest.completed');
    expect($events)->toHaveCount(1)
        ->and($events[0]->result)->toBe('failure')
        ->and(json_decode($events[0]->metadata, true)['status'])->toBe('failed');

    // The job's failed hook closes a run the worker could not finish.
    appDb()->table('users')->where('id', $this->admin->id)->update(['is_active' => true]);
    $second = $client->send('POST', TEST_RUNS_URI)->assertStatus(202)->json('data.id');
    (new RunSecuritySelfTestJob($second, $this->org->id))->failed(new RuntimeException('killed'));
    expect(runRow($second)->status)->toBe('failed');
});

it('selftest:recover fails what a dead worker left behind, and leaves live runs alone', function () {
    app(OrganizationContext::class)->run($this->org->id, function () {
        foreach ([
            'stale-running' => ['status' => 'running', 'heartbeat_at' => now()->subSeconds(SelfTestRecoverCommand::RUNNING_LIMIT_SECONDS + 5), 'created_at' => now()->subMinutes(20)],
            'live-running' => ['status' => 'running', 'heartbeat_at' => now()->subSeconds(10), 'created_at' => now()->subMinutes(20)],
            'stale-queued' => ['status' => 'queued', 'heartbeat_at' => null, 'created_at' => now()->subSeconds(SelfTestRecoverCommand::QUEUED_LIMIT_SECONDS + 5)],
        ] as $name => $attributes) {
            $org = $name === 'live-running' ? Organization::factory()->create()->id : ($name === 'stale-queued' ? Organization::factory()->create()->id : $this->org->id);
            appDb()->table('security_test_runs')->insert([
                'id' => $this->{$name} = (string) Str::uuid7(),
                'organization_id' => $org,
                'triggered_by' => null,
                'updated_at' => now()->toIso8601String(),
                ...array_map(fn ($value) => $value instanceof CarbonInterface ? $value->toIso8601String() : $value, $attributes),
            ]);
        }
    });

    expect(Artisan::call('selftest:recover'))->toBe(0);

    expect(runRow($this->{'stale-running'})->status)->toBe('failed')
        ->and(runRow($this->{'stale-running'})->error_code)->toBe('SELF_TEST_STALE')
        ->and(runRow($this->{'stale-queued'})->status)->toBe('failed')
        ->and(runRow($this->{'live-running'})->status)->toBe('running')
        ->and(selfTestEvents($this->org->id, 'selftest.completed'))->toHaveCount(1);
});

it('validates the list query and has no way to change a run', function () {
    $client = loggedIn($this, $this->admin);

    $client->send('GET', TEST_RUNS_URI.'?limit=0')->assertStatus(422);
    $client->send('GET', TEST_RUNS_URI.'?status=queued')->assertStatus(422)->assertJsonValidationErrors(['status']);
    $client->send('DELETE', TEST_RUNS_URI.'/019a0000-0000-7000-8000-000000000000')->assertStatus(405);
    $client->send('PATCH', TEST_RUNS_URI.'/019a0000-0000-7000-8000-000000000000', [])->assertStatus(405);
});
