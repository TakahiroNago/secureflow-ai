<?php

use App\Ai\AiGateway;
use App\Ai\AiRequest;
use App\Ai\AiResponse;
use App\Ai\Contracts\AiProvider;
use App\Ai\Providers\MockAiProvider;
use App\Ai\Providers\MockScenario;
use App\Console\Commands\AnalysisRecoverCommand;
use App\Domain\Workflow\AnalysisProcessor;
use App\Domain\Workflow\AnalysisService;
use App\Domain\Workflow\PlanHasher;
use App\Jobs\AnalyzeWorkflowJob;
use App\Models\AiAnalysisRequest;
use App\Models\Organization;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowRevision;
use App\Models\WorkflowTask;
use App\Support\Organization\OrganizationContext;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Sleep;
use Tests\Support\FailingAuditWriter;

/*
| docs/architecture.md §7 and §10: the worker's part of an analysis. The state in the database is the truth,
| whatever the queue does.
*/

uses(DatabaseTransactions::class);

beforeEach(function () {
    $this->org = Organization::factory()->create();
    $this->user = userIn($this->org->id);
    Sleep::fake();
});

function analysisRow(User $user, array $attributes = []): AiAnalysisRequest
{
    return app(OrganizationContext::class)->run($user->organization_id, function () use ($user, $attributes) {
        $analysis = new AiAnalysisRequest;
        $analysis->forceFill([
            'user_id' => $user->id,
            'status' => 'queued',
            'input_char_count' => 5,
            'input_scan_id' => insertScan(appDb(), $user->organization_id),
            ...$attributes,
        ])->save();

        return $analysis;
    });
}

function useMockScenario(MockScenario $scenario): void
{
    app()->bind(AiProvider::class, fn () => new MockAiProvider($scenario));
    app()->forgetInstance(AiGateway::class);
}

function runAnalysis(AiAnalysisRequest $analysis): void
{
    (new AnalyzeWorkflowJob($analysis->id, $analysis->organization_id))->handle(app(AnalysisProcessor::class), app(OrganizationContext::class));
}

function analysisState(AiAnalysisRequest $analysis): object
{
    return DB::table('ai_analysis_requests')->where('id', $analysis->id)->first();
}

function auditEvents(string $type): array
{
    return DB::table('audit_logs')->where('event_type', $type)->get()->all();
}

it('ST-01: a normal request becomes a draft workflow with its first revision and tasks', function () {
    $analysis = analysisRow($this->user);

    runAnalysis($analysis);

    $row = analysisState($analysis);
    expect($row->status)->toBe('succeeded')
        ->and($row->workflow_id)->not->toBeNull()
        ->and($row->error_code)->toBeNull()
        ->and($row->finished_at)->not->toBeNull()
        ->and($row->input_masked)->toBeNull();

    app(OrganizationContext::class)->run($this->org->id, function () use ($row) {
        $workflow = Workflow::query()->findOrFail($row->workflow_id);
        $revision = WorkflowRevision::query()->findOrFail($workflow->current_revision_id);
        $task = WorkflowTask::query()->where('workflow_id', $workflow->id)->sole();

        expect($workflow->status->value)->toBe('draft')
            ->and($workflow->created_by)->toBe($this->user->id)
            ->and($workflow->source_input_masked)->toBeNull()
            ->and($revision->revision_no)->toBe(1)
            ->and($revision->change_type)->toBe('ai_generated')
            ->and($revision->scan_id)->not->toBeNull()
            ->and($revision->scan_decision)->toBe('allow')
            ->and(PlanHasher::matches($revision->plan_snapshot, $revision->plan_hash))->toBeTrue()
            ->and($task->derived_permissions)->toBe(['ai.text.read'])
            ->and($task->policy_decision)->toBe('allowed');
    });
})->group('security');

it('records workflow.created in the same transaction, with no content', function () {
    runAnalysis(analysisRow($this->user));

    $events = auditEvents('workflow.created');

    expect($events)->toHaveCount(1)
        ->and($events[0]->actor_type)->toBe('user')
        ->and($events[0]->actor_user_id)->toBe($this->user->id)
        ->and($events[0]->organization_id)->toBe($this->org->id)
        ->and($events[0]->resource_type)->toBe('workflow')
        ->and(json_decode($events[0]->metadata, true))->toBe(['revision_no' => 1]);
});

it('does nothing when the job comes back: a job from an old snapshot cannot run the work twice', function () {
    $analysis = analysisRow($this->user);

    runAnalysis($analysis);
    runAnalysis($analysis);

    expect(DB::table('workflows')->count())->toBe(1)
        ->and(auditEvents('workflow.created'))->toHaveCount(1);
});

it('does nothing when another run has already claimed the row', function () {
    $analysis = analysisRow($this->user, ['status' => 'processing', 'started_at' => now(), 'heartbeat_at' => now()]);

    runAnalysis($analysis);

    expect(analysisState($analysis)->status)->toBe('processing')
        ->and(DB::table('workflows')->count())->toBe(0);
});

it('leaves a forbidden action in the plan, marked, with the server\'s permissions', function () {
    useMockScenario(MockScenario::ForbiddenAction);
    $analysis = analysisRow($this->user);

    runAnalysis($analysis);

    $tasks = DB::table('workflow_tasks')->orderBy('position')->get();

    expect(analysisState($analysis)->status)->toBe('succeeded')
        ->and($tasks->pluck('policy_decision')->all())->toBe(['forbidden', 'forbidden'])
        ->and(json_decode($tasks[1]->derived_permissions))->toBe(['system.shell']);
});

it('does not take permissions from what the AI asks for', function () {
    useMockScenario(MockScenario::PermissionInflation);

    runAnalysis(analysisRow($this->user));

    $task = DB::table('workflow_tasks')->first();

    expect(json_decode($task->derived_permissions))->toBe(['ai.text.read'])
        ->and(json_decode($task->ai_claimed_permissions))->toBe(['system.shell', 'external.http', 'admin.all']);
});

it('ST-07: fails the analysis on invalid AI output, and saves nothing', function (MockScenario $scenario) {
    useMockScenario($scenario);
    $analysis = analysisRow($this->user);

    runAnalysis($analysis);

    $row = analysisState($analysis);
    $events = auditEvents('analysis.failed');

    expect($row->status)->toBe('failed')
        ->and($row->error_code)->toBe('AI_INVALID_OUTPUT')
        ->and($row->workflow_id)->toBeNull()
        ->and(DB::table('workflows')->count())->toBe(0)
        ->and($events)->toHaveCount(1)
        ->and(json_decode($events[0]->metadata, true))->toBe(['analysis_id' => $analysis->id, 'reason_code' => 'AI_INVALID_OUTPUT']);
})->with([MockScenario::MalformedJson, MockScenario::ExtraKeys, MockScenario::Oversized, MockScenario::UnknownAction])->group('security');

it('fails the analysis when the provider keeps failing', function (MockScenario $scenario) {
    useMockScenario($scenario);
    $analysis = analysisRow($this->user);

    runAnalysis($analysis);

    expect(analysisState($analysis)->error_code)->toBe('AI_UNAVAILABLE')
        ->and(analysisState($analysis)->status)->toBe('failed');
})->with([MockScenario::Timeout, MockScenario::RateLimited, MockScenario::ServerError]);

it('stops when the user was made inactive after asking', function () {
    $analysis = analysisRow($this->user);
    $this->user->forceFill(['is_active' => false])->save();

    runAnalysis($analysis);

    expect(analysisState($analysis)->error_code)->toBe('USER_INACTIVE')
        ->and(DB::table('workflows')->count())->toBe(0);
});

it('saves nothing when the audit record cannot be written', function () {
    useAuditWriter(new FailingAuditWriter('53100', 'could not extend file: No space left on device'));
    $analysis = analysisRow($this->user);

    runAnalysis($analysis);

    expect(DB::table('workflows')->count())->toBe(0)
        ->and(DB::table('workflow_tasks')->count())->toBe(0)
        ->and(DB::table('workflow_revisions')->count())->toBe(0)
        ->and(analysisState($analysis)->status)->toBe('failed')
        ->and(analysisState($analysis)->error_code)->toBe('ANALYSIS_FAILED');
});

it('a late failure cannot undo a success', function () {
    $analysis = analysisRow($this->user);
    runAnalysis($analysis);

    app(OrganizationContext::class)->run($this->org->id, fn () => app(AnalysisProcessor::class)->fail($analysis->id, 'ANALYSIS_STALE'));

    expect(analysisState($analysis)->status)->toBe('succeeded')
        ->and(auditEvents('analysis.failed'))->toBe([]);
});

it('the job\'s failed hook closes the row', function () {
    $analysis = analysisRow($this->user, ['status' => 'processing']);

    (new AnalyzeWorkflowJob($analysis->id, $analysis->organization_id))->failed(new RuntimeException('killed'));

    expect(analysisState($analysis)->status)->toBe('failed')
        ->and(analysisState($analysis)->error_code)->toBe('ANALYSIS_FAILED');
});

// ---- Recovery ----------------------------------------------------------------------------------

it('gives up on rows a dead worker left behind, in every organization', function () {
    $otherUser = userIn(Organization::factory()->create()->id);
    $stuck = analysisRow($this->user, ['status' => 'processing', 'heartbeat_at' => now()->subSeconds(AnalysisRecoverCommand::PROCESSING_LIMIT_SECONDS + 1)]);
    $stuckElsewhere = analysisRow($otherUser, ['status' => 'processing', 'heartbeat_at' => now()->subSeconds(AnalysisRecoverCommand::PROCESSING_LIMIT_SECONDS + 1)]);
    $stuckQueued = analysisRow($this->user, ['created_at' => now()->subSeconds(AnalysisRecoverCommand::QUEUED_LIMIT_SECONDS + 1)]);

    expect(Artisan::call('analysis:recover'))->toBe(0);

    foreach ([$stuck, $stuckElsewhere, $stuckQueued] as $analysis) {
        expect(analysisState($analysis)->status)->toBe('failed')->and(analysisState($analysis)->error_code)->toBe('ANALYSIS_STALE');
    }

    expect(auditEvents('analysis.failed'))->toHaveCount(3);
});

it('leaves rows alone that may still be running or waiting', function () {
    $running = analysisRow($this->user, ['status' => 'processing', 'heartbeat_at' => now()->subSeconds(AnalysisRecoverCommand::PROCESSING_LIMIT_SECONDS - 5)]);
    $waiting = analysisRow($this->user);
    $done = analysisRow($this->user);
    runAnalysis($done);

    Artisan::call('analysis:recover');

    expect(analysisState($running)->status)->toBe('processing')
        ->and(analysisState($waiting)->status)->toBe('queued')
        ->and(analysisState($done)->status)->toBe('succeeded');
});

it('a run that was given up on saves nothing when it finally returns', function () {
    $analysis = analysisRow($this->user);

    // As if recovery acted during the AI call.
    app()->bind(AiProvider::class, function () use ($analysis) {
        return new class($analysis) implements AiProvider
        {
            public function __construct(private readonly AiAnalysisRequest $analysis) {}

            public function generate(AiRequest $request): AiResponse
            {
                app(AnalysisProcessor::class)->fail($this->analysis->id, 'ANALYSIS_STALE');

                return (new MockAiProvider)->generate($request);
            }
        };
    });

    runAnalysis($analysis);

    expect(analysisState($analysis)->error_code)->toBe('ANALYSIS_STALE')
        ->and(DB::table('workflows')->count())->toBe(0);
});

// ---- The queue ---------------------------------------------------------------------------------

it('keeps the limits in the right order, so a job is never cut off while retrying', function () {
    $job = new AnalyzeWorkflowJob('id', 'org');

    expect($job->timeout)->toBeGreaterThan(app(AiGateway::class)->worstCaseSeconds())
        ->and(config('queue.connections.database.retry_after'))->toBeGreaterThan($job->timeout)
        ->and(AnalysisRecoverCommand::PROCESSING_LIMIT_SECONDS)->toBeGreaterThan($job->timeout)
        ->and($job->tries)->toBe(1)
        ->and($job->failOnTimeout)->toBeTrue();
});

it('pushes the job inside the transaction: after the commit, a crash in between would lose it', function () {
    expect(config('queue.connections.database.after_commit'))->toBeFalse()
        ->and(config('queue.connections.database.driver'))->toBe('database');
});

it('commits the job with the row, and rolls both back together', function () {
    config(['queue.default' => 'database']);

    try {
        app(OrganizationContext::class)->run($this->org->id, fn () => DB::transaction(function () {
            app(AnalysisService::class)->request($this->user, 5);

            expect(DB::table('jobs')->count())->toBe(1);

            throw new RuntimeException('roll back');
        }));
    } catch (RuntimeException) {
        // Expected.
    }

    expect(DB::table('jobs')->count())->toBe(0)
        ->and(DB::table('ai_analysis_requests')->count())->toBe(0);
});

it('puts ids in the job and nothing else', function () {
    config(['queue.default' => 'database']);

    $analysis = app(OrganizationContext::class)->run($this->org->id, fn () => app(AnalysisService::class)->request($this->user, 5));
    $job = DB::table('jobs')->sole();

    expect($job->queue)->toBe('ai')
        ->and($job->payload)->toContain($analysis->id)
        ->and($job->payload)->not->toContain($this->user->email)
        ->and(array_keys(get_object_vars(unserialize(json_decode($job->payload)->data->command))))->toContain('analysisId', 'organizationId');
});

it('runs through a real worker on the database queue', function () {
    config(['queue.default' => 'database']);

    $analysis = app(OrganizationContext::class)->run($this->org->id, fn () => app(AnalysisService::class)->request($this->user, 5));

    Artisan::call('queue:work', ['connection' => 'database', '--queue' => 'ai', '--once' => true]);

    expect(analysisState($analysis)->status)->toBe('succeeded')
        ->and(DB::table('jobs')->count())->toBe(0);
});

it('tells business state from the queue: a job that comes back after a crash fails the row, and only that', function () {
    config(['queue.default' => 'database']);

    $analysis = app(OrganizationContext::class)->run($this->org->id, fn () => app(AnalysisService::class)->request($this->user, 5));
    DB::table('jobs')->update(['attempts' => 1, 'reserved_at' => now()->subSeconds(200)->getTimestamp()]);

    Artisan::call('queue:work', ['connection' => 'database', '--queue' => 'ai', '--once' => true]);

    expect(DB::table('failed_jobs')->count())->toBe(1)
        ->and(analysisState($analysis)->status)->toBe('failed')
        ->and(analysisState($analysis)->error_code)->toBe('ANALYSIS_FAILED')
        ->and(DB::table('failed_jobs')->value('exception'))->not->toContain($this->user->email);
});

it('dispatches to the ai queue', function () {
    Queue::fake();

    app(OrganizationContext::class)->run($this->org->id, fn () => app(AnalysisService::class)->request($this->user, 5));

    Queue::assertPushedOn('ai', AnalyzeWorkflowJob::class);
});
