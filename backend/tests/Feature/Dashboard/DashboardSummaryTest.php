<?php

use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Domain\Dashboard\DashboardSummary;
use App\Models\AiAnalysisRequest;
use App\Models\Organization;
use App\Models\User;
use App\Models\Workflow;
use App\Support\Organization\OrganizationContext;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Tests\Support\FailingAuditWriter;

/*
| docs/api-design.md §3.2, with fixed data: every expected number below is written out by hand.
*/

uses(DatabaseTransactions::class);

const DASHBOARD = '/api/v1/dashboard/summary';

/** A row in a given state, with the approval and execution rows it needs. */
function executedWorkflow(User $creator, User $admin, string $status = 'completed'): Workflow
{
    $workflow = workflowOf($creator, ['status' => 'completed']);
    $revision = insertRevision(appDb(), $workflow);
    $approval = insertApproval(appDb(), $workflow, $revision, $admin->id);
    insertExecution(appDb(), $workflow, $revision, $approval, ['status' => $status]);

    return $workflow;
}

function analysisFor(User $user, array $attributes = []): void
{
    app(OrganizationContext::class)->run($user->organization_id, function () use ($user, $attributes) {
        (new AiAnalysisRequest)->forceFill(['user_id' => $user->id, 'status' => 'queued', 'input_char_count' => 1, 'input_scan_id' => insertScan(appDb(), $user->organization_id), ...$attributes])->save();
    });
}

beforeEach(function () {
    $this->org = Organization::factory()->create();
    $this->member = userIn($this->org->id);
    $this->otherMember = userIn($this->org->id);
    $this->admin = userIn($this->org->id, 'admin');
    $this->auditor = userIn($this->org->id, 'auditor');

    // The member: 2 draft, 1 pending, 1 completed and executed. Another member: 1 draft, 1 pending.
    workflowOf($this->member);
    workflowOf($this->member);
    workflowOf($this->member, ['status' => 'pending']);
    executedWorkflow($this->member, $this->admin);
    workflowOf($this->otherMember);
    workflowOf($this->otherMember, ['status' => 'pending']);

    // This must never be counted by anyone here.
    $elsewhere = Organization::factory()->create();
    $outsider = userIn($elsewhere->id);
    workflowOf($outsider, ['status' => 'pending']);
    executedWorkflow($outsider, userIn($elsewhere->id, 'admin'));
    analysisFor($outsider);

    analysisFor($this->member);
    analysisFor($this->member);
    analysisFor($this->otherMember);
});

function summaryOf(User $user): array
{
    return app(OrganizationContext::class)->run($user->organization_id, fn () => app(DashboardSummary::class)->for($user));
}

it('counts a member\'s own work only', function () {
    $summary = summaryOf($this->member);

    expect($summary['workflows']['total'])->toBe(4)
        ->and($summary['workflows']['by_status'])->toBe(['draft' => 2, 'pending' => 1, 'approved' => 0, 'running' => 0, 'completed' => 1, 'rejected' => 0, 'failed' => 0])
        ->and($summary['pending_approval'])->toBe(1)
        ->and($summary['executed'])->toBe(1)
        ->and($summary['analyses_this_month'])->toBe(2);
});

it('counts the whole organization for an admin or auditor, and nothing from another', function (string $who) {
    $summary = summaryOf($this->{$who});

    expect($summary['workflows']['total'])->toBe(6)
        ->and($summary['workflows']['by_status']['draft'])->toBe(3)
        ->and($summary['pending_approval'])->toBe(2)
        ->and($summary['executed'])->toBe(1)
        ->and($summary['analyses_this_month'])->toBe(3);
})->with(['admin', 'auditor']);

it('counts a member with nothing as real zeros, in every status', function () {
    $summary = summaryOf(userIn($this->org->id));

    expect($summary['workflows']['total'])->toBe(0)
        ->and(array_sum($summary['workflows']['by_status']))->toBe(0)
        ->and($summary['workflows']['by_status'])->toHaveCount(7)
        ->and($summary['executed'])->toBe(0);
});

it('counts only finished executions as executed', function (string $status) {
    $user = userIn($this->org->id);
    executedWorkflow($user, $this->admin, $status);

    expect(summaryOf($user)['executed'])->toBe(0);
})->with(['queued', 'running', 'failed']);

it('counts this month only, in UTC', function () {
    $user = userIn($this->org->id);
    $this->travelTo('2026-11-15 12:00:00');
    analysisFor($user, ['created_at' => '2026-11-01 00:00:00+00']);
    analysisFor($user, ['created_at' => '2026-10-31 23:59:59+00']);

    expect(summaryOf($user)['analyses_this_month'])->toBe(1);
});

it('says that what does not exist yet does not exist: null, never 0', function (string $role) {
    $summary = summaryOf(userIn($this->org->id, $role));

    expect($summary['ai_usage'])->toEqual(['tokens' => 0, 'estimated_cost' => 0])
        ->and($summary['self_test'])->toBe(['latest' => null, 'available_from_step' => '3-3']);
})->with(['admin', 'member', 'auditor']);

// ---- Recent operations --------------------------------------------------------------------------

function recordedBy(User $user, AuditEventType $type = AuditEventType::Logout): void
{
    app(AuditLogger::class)->recordAfterTransaction(AuditEntry::byUser($type, $user), 'test');
}

it('shows a member their own operations only', function () {
    recordedBy($this->member);
    recordedBy($this->otherMember);
    recordedBy($this->admin);

    $operations = summaryOf($this->member)['recent_operations'];

    expect($operations)->toHaveCount(1)
        ->and($operations[0]['actor'])->toBe(['id' => $this->member->id, 'name' => $this->member->name])
        ->and($operations[0]['event_type'])->toBe('auth.logout');
});

it('shows an admin or auditor everyone in the organization, and nobody elsewhere', function (string $who) {
    $outsider = userIn(Organization::factory()->create()->id);
    recordedBy($this->member);
    recordedBy($this->admin);
    recordedBy($outsider);

    $actors = array_column(array_column(summaryOf($this->{$who})['recent_operations'], 'actor'), 'id');

    expect($actors)->toContain($this->member->id, $this->admin->id)->not->toContain($outsider->id);
})->with(['admin', 'auditor']);

it('never shows the system chain', function () {
    app(AuditLogger::class)->recordAfterTransaction(
        AuditEntry::anonymous(AuditEventType::LoginFailed, null, 'failure', ['reason_code' => 'UNKNOWN_ACCOUNT']),
        'test',
    );

    expect(summaryOf($this->admin)['recent_operations'])->toBe([]);
});

it('shows only the listed events', function (AuditEventType $type) {
    app(AuditLogger::class)->recordAfterTransaction(AuditEntry::system($type, $this->member, 'failure', ['reason_code' => 'X']), 'test');

    expect(summaryOf($this->admin)['recent_operations'])->toBe([]);
})->with([AuditEventType::Locked, AuditEventType::AnalysisFailed, AuditEventType::PasswordChanged]);

it('gives no address, no metadata and no hash', function () {
    app(AuditLogger::class)->recordAfterTransaction(
        AuditEntry::byUserOn(AuditEventType::WorkflowUpdated, $this->member, 'workflow', (string) Str::uuid7(), ['revision_no' => 3, 'change' => 'task']),
        'test',
    );

    $operation = summaryOf($this->member)['recent_operations'][0];

    expect(array_keys($operation))->toBe(['id', 'event_type', 'actor', 'resource_type', 'resource_id', 'result', 'occurred_at'])
        ->and(json_encode($operation))->not->toContain('revision_no');
});

it('shows the newest 10, newest first', function () {
    foreach (range(1, 12) as $i) {
        $this->travel(1)->seconds();
        recordedBy($this->member);
    }

    $times = array_column(summaryOf($this->member)['recent_operations'], 'occurred_at');
    $sorted = $times;
    rsort($sorted);

    expect($times)->toHaveCount(10)->toBe($sorted);
});

// ---- Over HTTP -----------------------------------------------------------------------------------

it('answers each role over HTTP with its own numbers', function (string $who, int $total) {
    loggedIn($this, $this->{$who})->send('GET', DASHBOARD)
        ->assertOk()
        ->assertJsonPath('data.workflows.total', $total)
        ->assertJsonPath('data.ai_usage.tokens', 0);
})->with([
    'member' => ['member', 4],
    'admin' => ['admin', 6],
    'auditor' => ['auditor', 6],
]);

it('answers 401 without a session', function () {
    spa($this)->csrf()->send('GET', DASHBOARD)->assertStatus(401);
});

it('ST-34: has authentication, an organization and a policy', function () {
    expect(Route::getRoutes()->getByName('dashboard.summary')->gatherMiddleware())
        ->toContain('auth:sanctum', 'session.current', 'org.context', 'can:viewAny,App\Models\Workflow');
})->group('security');

it('keeps reading while the audit log cannot be written, as reads do', function () {
    $client = loggedIn($this, $this->member);
    useAuditWriter(new FailingAuditWriter('53100', 'could not extend file: No space left on device'));
    recordedBy($this->member);

    $client->send('GET', DASHBOARD)->assertOk();
});

it('reads with no write at all', function () {
    $before = [DB::table('audit_logs')->count(), DB::table('workflows')->count()];

    loggedIn($this, $this->member)->send('GET', DASHBOARD)->assertOk();

    // The login is one audit record, and the dashboard adds none.
    expect([DB::table('audit_logs')->count(), DB::table('workflows')->count()])->toBe([$before[0] + 1, $before[1]]);
});
