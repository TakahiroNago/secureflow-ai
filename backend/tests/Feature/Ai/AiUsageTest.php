<?php

use App\Ai\AiFailure;
use App\Ai\AiGateway;
use App\Ai\AiProviderException;
use App\Ai\AiRequest;
use App\Ai\AiResponse;
use App\Ai\AiTokens;
use App\Ai\Contracts\AiProvider;
use App\Domain\Workflow\AnalysisProcessor;
use App\Jobs\AnalyzeWorkflowJob;
use App\Models\AiAnalysisRequest;
use App\Models\Organization;
use App\Models\OrganizationSetting;
use App\Models\User;
use App\Support\Organization\OrganizationContext;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Sleep;
use Illuminate\Support\Str;

/*
| ST-30 and the usage log (docs/security-design.md §6, docs/database-design.md §3.13).
*/

uses(DatabaseTransactions::class);

const USAGE_ANALYSES = '/api/v1/analyses';

const USAGE_SUMMARY = '/api/v1/ai-usage/summary';

function aiThatAnswers(Closure $answer): object
{
    $provider = new class($answer) implements AiProvider
    {
        public int $calls = 0;

        public function __construct(private Closure $answer) {}

        public function generate(AiRequest $request): AiResponse
        {
            $this->calls++;

            return ($this->answer)();
        }
    };
    app()->instance(AiProvider::class, $provider);
    app()->forgetInstance(AiGateway::class);

    return $provider;
}

function goodPlan(?AiTokens $tokens = null): AiResponse
{
    $task = ['title' => '要約', 'description' => '説明', 'action_type' => 'text.summarize', 'steps' => ['読む'], 'priority' => 'low', 'requested_permissions' => ['ai.text.read'], 'target_data' => '本文', 'impact_summary' => 'なし'];

    return new AiResponse(json_encode(['tasks' => [$task]], JSON_UNESCAPED_UNICODE), $tokens, 'gpt-6-luna', 'req_1');
}

function queuedAnalysis(User $user): AiAnalysisRequest
{
    return app(OrganizationContext::class)->run($user->organization_id, function () use ($user) {
        $analysis = new AiAnalysisRequest;
        $analysis->forceFill(['user_id' => $user->id, 'status' => 'queued', 'input_masked' => '週次の報告', 'input_char_count' => 5, 'input_scan_id' => insertScan(appDb(), $user->organization_id)])->save();

        return $analysis;
    });
}

function runQueued(AiAnalysisRequest $analysis): void
{
    (new AnalyzeWorkflowJob($analysis->id, $analysis->organization_id))->handle(app(AnalysisProcessor::class), app(OrganizationContext::class));
}

function usageRow(array $overrides = []): void
{
    appDb()->table('ai_usage_logs')->insert($overrides + [
        'id' => (string) Str::uuid7(),
        'provider' => 'openai',
        'purpose' => 'task_generation',
        'status' => 'success',
        'created_at' => now()->toIso8601String(),
    ]);
}

function limitsOf(string $organizationId, int $tokens, int $requests): void
{
    OrganizationSetting::factory()->create(['organization_id' => $organizationId, 'monthly_token_limit' => $tokens, 'user_daily_request_limit' => $requests]);
}

beforeEach(function () {
    // As in production: a job waits in the table. The test default would run it inside the request.
    config(['queue.default' => 'database']);

    $this->org = Organization::factory()->create();
    $this->user = userIn($this->org->id);
});

// ---- ST-30 ------------------------------------------------------------------------------------------

it('ST-30: refuses with 429 at the daily limit, and never calls the AI', function () {
    $ai = aiThatAnswers(fn () => goodPlan());
    limitsOf($this->org->id, 1000, 1);
    usageRow(['organization_id' => $this->org->id, 'user_id' => $this->user->id]);

    loggedIn($this, $this->user)->send('POST', USAGE_ANALYSES, ['input' => '週次の報告'])
        ->assertStatus(429)->assertJsonPath('code', 'AI_LIMIT_EXCEEDED');

    $row = DB::table('ai_usage_logs')->where('status', 'budget_blocked')->sole();
    $audit = DB::table('audit_logs')->where('event_type', 'ai.call')->where('organization_id', $this->org->id)->sole();

    expect($ai->calls)->toBe(0)
        ->and(DB::table('ai_analysis_requests')->where('user_id', $this->user->id)->count())->toBe(0)
        ->and($row->error_code)->toBe('USER_DAILY_LIMIT')
        ->and($audit->result)->toBe('denied')
        ->and(json_decode((string) $audit->metadata, true)['reason_code'])->toBe('USER_DAILY_LIMIT');
});

it('ST-30: refuses at the monthly limit of the organization, whoever used it', function () {
    limitsOf($this->org->id, 100, 50);
    usageRow(['organization_id' => $this->org->id, 'user_id' => userIn($this->org->id)->id, 'total_tokens' => 100]);

    loggedIn($this, $this->user)->send('POST', USAGE_ANALYSES, ['input' => '週次の報告'])
        ->assertStatus(429)->assertJsonPath('code', 'AI_LIMIT_EXCEEDED');

    expect(DB::table('ai_usage_logs')->where('status', 'budget_blocked')->value('error_code'))->toBe('ORGANIZATION_MONTHLY_LIMIT');
});

it('ST-30: refuses in the worker too, since a job can wait, and never calls the AI', function () {
    $ai = aiThatAnswers(fn () => goodPlan());
    limitsOf($this->org->id, 100, 50);
    $analysis = queuedAnalysis($this->user);
    usageRow(['organization_id' => $this->org->id, 'user_id' => $this->user->id, 'total_tokens' => 100]);

    runQueued($analysis);

    $row = DB::table('ai_analysis_requests')->where('id', $analysis->id)->first();

    expect($ai->calls)->toBe(0)
        ->and($row->status)->toBe('failed')
        ->and($row->error_code)->toBe('AI_LIMIT_EXCEEDED')
        ->and($row->input_masked)->toBeNull()
        ->and(DB::table('ai_usage_logs')->where('analysis_request_id', $analysis->id)->value('status'))->toBe('budget_blocked');
});

it('ST-30: passes just below the limits', function () {
    limitsOf($this->org->id, 101, 2);
    usageRow(['organization_id' => $this->org->id, 'user_id' => $this->user->id, 'total_tokens' => 100]);

    loggedIn($this, $this->user)->send('POST', USAGE_ANALYSES, ['input' => '週次の報告'])->assertStatus(202);
});

it('ST-30: last month and yesterday do not count, and neither does another organization', function () {
    limitsOf($this->org->id, 100, 1);
    $other = Organization::factory()->create();
    usageRow(['organization_id' => $other->id, 'user_id' => userIn($other->id)->id, 'total_tokens' => 100]);
    usageRow(['organization_id' => $this->org->id, 'user_id' => $this->user->id, 'total_tokens' => 100, 'created_at' => now('UTC')->startOfMonth()->subSecond()->toIso8601String()]);

    loggedIn($this, $this->user)->send('POST', USAGE_ANALYSES, ['input' => '週次の報告'])->assertStatus(202);
});

it('ST-30: a refusal does not use up the day', function () {
    limitsOf($this->org->id, 1000, 1);
    usageRow(['organization_id' => $this->org->id, 'user_id' => $this->user->id, 'status' => 'budget_blocked']);

    loggedIn($this, $this->user)->send('POST', USAGE_ANALYSES, ['input' => '週次の報告'])->assertStatus(202);
});

it('ST-30: an organization with no settings still has limits', function () {
    foreach (range(1, 100) as $ignored) {
        usageRow(['organization_id' => $this->org->id, 'user_id' => $this->user->id]);
    }

    loggedIn($this, $this->user)->send('POST', USAGE_ANALYSES, ['input' => '週次の報告'])
        ->assertStatus(429)->assertJsonPath('code', 'AI_LIMIT_EXCEEDED');
});

// ---- The record of a call ---------------------------------------------------------------------------

it('records what a call used, with no text, in the log and the audit chain', function () {
    aiThatAnswers(fn () => goodPlan(new AiTokens(3000, 2000, 5000)));
    $analysis = queuedAnalysis($this->user);

    runQueued($analysis);

    $row = DB::table('ai_usage_logs')->where('analysis_request_id', $analysis->id)->sole();
    $audit = DB::table('audit_logs')->where('event_type', 'ai.call')->where('resource_id', $analysis->id)->sole();

    expect($row->status)->toBe('success')
        ->and($row->user_id)->toBe($this->user->id)
        ->and($row->organization_id)->toBe($this->org->id)
        ->and($row->prompt_tokens)->toBe(3000)
        ->and($row->completion_tokens)->toBe(2000)
        ->and($row->total_tokens)->toBe(5000)
        ->and($row->estimated_cost_micros)->toBe(1300)
        ->and($row->model)->toBe('gpt-6-luna')
        ->and($row->provider_request_id)->toBe('req_1')
        ->and($row->latency_ms)->toBeInt()
        ->and(json_encode($row))->not->toContain('週次')
        ->and(json_decode((string) $audit->metadata, true))->toEqual(['provider' => 'mock', 'model' => 'gpt-6-luna', 'total_tokens' => 5000]);
});

it('records a failure by its kind, and what it still used', function (AiFailure $failure, string $status, string $errorCode) {
    aiThatAnswers(fn () => throw new AiProviderException($failure, tokens: new AiTokens(1, 2, 3)));
    $analysis = queuedAnalysis($this->user);

    runQueued($analysis);

    $row = DB::table('ai_usage_logs')->where('analysis_request_id', $analysis->id)->sole();

    expect($row->status)->toBe($status)
        ->and($row->error_code)->toBe($failure->value)
        ->and($row->total_tokens)->toBe(3)
        ->and(DB::table('ai_analysis_requests')->where('id', $analysis->id)->value('error_code'))->toBe($errorCode)
        ->and(DB::table('audit_logs')->where('event_type', 'ai.call')->where('resource_id', $analysis->id)->sole()->result)->toBe('failure');
})->with([
    [AiFailure::Rejected, 'error', 'AI_UNAVAILABLE'],
    [AiFailure::Unauthorized, 'error', 'AI_UNAVAILABLE'],
    [AiFailure::QuotaExceeded, 'error', 'AI_UNAVAILABLE'],
    [AiFailure::Refused, 'invalid_output', 'AI_INVALID_OUTPUT'],
    [AiFailure::Incomplete, 'invalid_output', 'AI_INVALID_OUTPUT'],
    [AiFailure::Malformed, 'invalid_output', 'AI_INVALID_OUTPUT'],
]);

it('tells a timeout and a rate limit apart in the log', function (AiFailure $failure, string $status) {
    Sleep::fake();
    aiThatAnswers(fn () => throw new AiProviderException($failure));
    $analysis = queuedAnalysis($this->user);

    runQueued($analysis);

    expect(DB::table('ai_usage_logs')->where('analysis_request_id', $analysis->id)->value('status'))->toBe($status);
})->with([
    [AiFailure::Timeout, 'timeout'],
    [AiFailure::RateLimited, 'rate_limited'],
    [AiFailure::ServerError, 'error'],
]);

it('keeps no tokens for the mock, rather than zero', function () {
    $analysis = queuedAnalysis($this->user);

    runQueued($analysis);

    $row = DB::table('ai_usage_logs')->where('analysis_request_id', $analysis->id)->sole();

    expect($row->status)->toBe('success')
        ->and($row->total_tokens)->toBeNull()
        ->and($row->estimated_cost_micros)->toBeNull();
});

it('is append-only, for the application too', function () {
    usageRow(['organization_id' => $this->org->id, 'user_id' => $this->user->id]);

    expect(dbError(appDb(), fn ($db) => $db->table('ai_usage_logs')->update(['status' => 'error'])))->not->toBeNull()
        ->and(dbError(appDb(), fn ($db) => $db->table('ai_usage_logs')->delete()))->not->toBeNull();
});

it('cannot belong to a user of another organization', function () {
    $other = Organization::factory()->create();

    expect(dbError(appDb(), fn () => usageRow(['organization_id' => $this->org->id, 'user_id' => userIn($other->id)->id])))->not->toBeNull();
});

// ---- Reading ----------------------------------------------------------------------------------------

it('sums the use by role: a member their own, an admin and an auditor the organization', function (string $role, int $tokens, bool $budgetShown) {
    limitsOf($this->org->id, 1000, 10);
    $viewer = userIn($this->org->id, $role);
    usageRow(['organization_id' => $this->org->id, 'user_id' => $viewer->id, 'prompt_tokens' => 60, 'completion_tokens' => 40, 'total_tokens' => 100, 'estimated_cost_micros' => 2_500]);
    usageRow(['organization_id' => $this->org->id, 'user_id' => $this->user->id, 'prompt_tokens' => 10, 'completion_tokens' => 10, 'total_tokens' => 20, 'estimated_cost_micros' => 500]);
    usageRow(['organization_id' => $this->org->id, 'user_id' => $this->user->id, 'status' => 'budget_blocked']);

    $data = loggedIn($this, $viewer)->send('GET', USAGE_SUMMARY)->assertOk()->json('data');

    expect($data['tokens']['total'])->toBe($tokens)
        ->and($data['limits']['user_daily_requests'])->toEqual(['used' => 1, 'limit' => 10, 'ratio' => 0.1])
        ->and($data['limits']['organization_monthly_tokens'] !== null)->toBe($budgetShown);

    if ($budgetShown) {
        expect($data['requests'])->toBe(2)
            ->and($data['estimated_cost_usd'])->toEqual(0.003)
            ->and($data['limits']['organization_monthly_tokens'])->toEqual(['used' => 120, 'limit' => 1000, 'ratio' => 0.12]);
    }
})->with([
    ['member', 100, false],
    ['admin', 120, true],
    ['auditor', 120, true],
]);

it('takes the day or the month', function () {
    // The middle of a month, whatever day this runs on.
    $this->travelTo(now('UTC')->startOfMonth()->addDays(10)->addHours(3));
    usageRow(['organization_id' => $this->org->id, 'user_id' => $this->user->id, 'total_tokens' => 5]);
    usageRow(['organization_id' => $this->org->id, 'user_id' => $this->user->id, 'total_tokens' => 7, 'created_at' => now('UTC')->subDay()->toIso8601String()]);
    $client = loggedIn($this, $this->user);

    $client->send('GET', USAGE_SUMMARY.'?period=day')->assertOk()->assertJsonPath('data.period', 'day')->assertJsonPath('data.tokens.total', 5);
    $client->send('GET', USAGE_SUMMARY.'?period=month')->assertOk()->assertJsonPath('data.tokens.total', 12);
    $client->send('GET', USAGE_SUMMARY)->assertOk()->assertJsonPath('data.period', 'month');
    $client->send('GET', USAGE_SUMMARY.'?period=week')->assertStatus(422);
});

it('does not show another organization', function () {
    $other = Organization::factory()->create();
    usageRow(['organization_id' => $other->id, 'user_id' => userIn($other->id)->id, 'total_tokens' => 999]);

    loggedIn($this, userIn($this->org->id, 'admin'))->send('GET', USAGE_SUMMARY)->assertOk()->assertJsonPath('data.tokens.total', 0);
});

it('shows the use on the dashboard, by role', function () {
    usageRow(['organization_id' => $this->org->id, 'user_id' => $this->user->id, 'total_tokens' => 20, 'estimated_cost_micros' => 500_000]);
    usageRow(['organization_id' => $this->org->id, 'user_id' => userIn($this->org->id)->id, 'total_tokens' => 100, 'estimated_cost_micros' => 1_000_000]);

    loggedIn($this, $this->user)->send('GET', '/api/v1/dashboard/summary')->assertOk()
        ->assertJsonPath('data.ai_usage.tokens', 20)
        ->assertJsonPath('data.ai_usage.estimated_cost', 0.5);

    loggedIn($this, userIn($this->org->id, 'auditor'))->send('GET', '/api/v1/dashboard/summary')->assertOk()
        ->assertJsonPath('data.ai_usage.tokens', 120)
        ->assertJsonPath('data.ai_usage.estimated_cost', 1.5);
});
