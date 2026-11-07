<?php

use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Audit\AuditWriter;
use App\Console\Commands\ExecutionsReapStaleCommand;
use App\Domain\Execution\ExecutionProcessor;
use App\Domain\Execution\ExecutionService;
use App\Domain\Execution\ExecutionSimulator;
use App\Domain\Execution\ExecutionVerifier;
use App\Domain\Workflow\AnalysisProcessor;
use App\Domain\Workflow\PlanHasher;
use App\Domain\Workflow\WorkflowRevisions;
use App\Jobs\AnalyzeWorkflowJob;
use App\Jobs\ExecuteWorkflowJob;
use App\Models\AiAnalysisRequest;
use App\Models\Approval;
use App\Models\Organization;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowRevision;
use App\Models\WorkflowTask;
use App\Security\Policy\ActionCatalog;
use App\Security\Policy\PolicyDecision;
use App\Support\Organization\OrganizationContext;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Tests\Support\FailingAuditWriter;
use Tests\Support\SpaClient;

/*
| docs/api-design.md §3.6, docs/security-design.md §10, §11. ST-08, 22, 33 and 37, and AUTH-LOCK-03, for execution.
| The race and a real killed worker are in scripts/test-workflow-flow.sh and scripts/test-execution-failure.sh.
*/

uses(DatabaseTransactions::class);

const EXECUTION_WORKFLOWS = '/api/v1/workflows/';

const A_KEY = 'key-1';

function runnablePlan(User $owner, User $approver): string
{
    $analysis = app(OrganizationContext::class)->run($owner->organization_id, function () use ($owner) {
        $analysis = new AiAnalysisRequest;
        $analysis->forceFill(['user_id' => $owner->id, 'status' => 'queued', 'input_char_count' => 1, 'input_scan_id' => insertScan(appDb(), $owner->organization_id)])->save();

        return $analysis;
    });
    (new AnalyzeWorkflowJob($analysis->id, $analysis->organization_id))->handle(app(AnalysisProcessor::class), app(OrganizationContext::class));

    $id = (string) DB::table('ai_analysis_requests')->where('id', $analysis->id)->value('workflow_id');
    $revision = DB::table('workflow_revisions')->where('workflow_id', $id)->sole();
    insertApproval(appDb(), Workflow::query()->withoutGlobalScopes()->findOrFail($id), $revision->id, $approver->id, ['plan_hash' => $revision->plan_hash]);
    DB::table('workflows')->where('id', $id)->update(['status' => 'approved']);

    return $id;
}

function requestExecution(SpaClient $client, string $id, ?string $key = A_KEY): TestResponse
{
    return $client->send('POST', EXECUTION_WORKFLOWS.$id.'/execute', null, $key === null ? [] : ['HTTP_IDEMPOTENCY_KEY' => $key]);
}

function runJob(string $executionId, string $organizationId): void
{
    (new ExecuteWorkflowJob($executionId, $organizationId))->handle(app(ExecutionProcessor::class), app(OrganizationContext::class));
}

function workflowStatus(string $id): string
{
    return (string) DB::table('workflows')->where('id', $id)->value('status');
}

function executionRow(string $id): ?object
{
    return DB::table('workflow_executions')->where('workflow_id', $id)->first();
}

function executionAudit(string $id, string $type): Collection
{
    return DB::table('audit_logs')->where('event_type', $type)->where('resource_id', $id)->orderBy('chain_seq')->get();
}

function executionDenials(string $id): array
{
    return executionAudit($id, 'execution.denied')->map(fn ($row) => json_decode((string) $row->metadata, true)['reason_code'])->all();
}

/** The current revision replaced by one with its own hash, scan and approval, which the test then says something about. */
function reviseWith(string $id, User $approver, array $revision = []): string
{
    $workflow = app(OrganizationContext::class)->run(DB::table('workflows')->where('id', $id)->value('organization_id'), function () use ($id) {
        return Workflow::query()->findOrFail($id);
    });
    $tasks = app(OrganizationContext::class)->run($workflow->organization_id, fn () => WorkflowTask::query()->where('workflow_id', $id)->orderBy('position')->get());
    $policy = $revision['policy_version'] ?? ActionCatalog::VERSION;
    $no = (int) DB::table('workflow_revisions')->where('workflow_id', $id)->max('revision_no') + 1;
    $snapshot = WorkflowRevisions::snapshotOf($workflow, $no, $policy, $tasks);
    $hash = PlanHasher::hash($snapshot);

    $row = insertRevision(appDb(), $workflow, [
        'revision_no' => $no,
        'plan_snapshot' => json_encode($snapshot, JSON_UNESCAPED_UNICODE),
        'plan_hash' => $hash,
        'policy_version' => $policy,
        ...array_diff_key($revision, ['policy_version' => true]),
    ]);
    insertApproval(appDb(), $workflow, $row, $approver->id, ['plan_hash' => $hash]);
    DB::table('workflows')->where('id', $id)->update(['current_revision_id' => $row]);

    return $row;
}

beforeEach(function () {
    // As in production: a job waits in the table, in the transaction that queued it. The test default runs it at once.
    config(['queue.default' => 'database']);

    $this->org = Organization::factory()->create();
    $this->owner = userIn($this->org->id);
    $this->admin = userIn($this->org->id, 'admin');
    $this->id = runnablePlan($this->owner, $this->admin);
});

// ---- Requesting -------------------------------------------------------------------------------------

it('accepts an approved plan: the row, the state, the record and the job together', function () {
    $response = requestExecution(loggedIn($this, $this->owner), $this->id)->assertStatus(202);

    $row = executionRow($this->id);

    expect($response->json('data.execution_id'))->toBe($row->id)
        ->and($response->json('data.status'))->toBe('queued')
        ->and($row->status)->toBe('queued')
        ->and($row->requested_by)->toBe($this->owner->id)
        ->and(workflowStatus($this->id))->toBe('running')
        ->and(DB::table('jobs')->where('queue', 'execution')->where('payload', 'like', '%'.$row->id.'%')->count())->toBe(1);

    $audit = executionAudit($this->id, 'execution.started')->sole();

    expect($audit->actor_user_id)->toBe($this->owner->id)
        ->and(json_decode((string) $audit->metadata, true))->toEqual(['execution_id' => $row->id, 'revision_no' => 1]);
});

it('lets an admin other than the owner execute', function () {
    requestExecution(loggedIn($this, userIn($this->org->id, 'admin')), $this->id)->assertStatus(202);
});

it('puts no text on the queue', function () {
    requestExecution(loggedIn($this, $this->owner), $this->id)->assertStatus(202);
    $title = (string) DB::table('workflow_tasks')->where('workflow_id', $this->id)->value('title');

    expect(DB::table('jobs')->where('queue', 'execution')->value('payload'))->not->toContain($title);
});

it('needs a key of the right form', function (?string $key) {
    requestExecution(loggedIn($this, $this->owner), $this->id, $key)
        ->assertStatus(422)->assertJsonValidationErrors(['idempotency_key']);

    expect(executionRow($this->id))->toBeNull()->and(workflowStatus($this->id))->toBe('approved');
})->with([[null], [''], ['with space'], [str_repeat('a', 101)]]);

it('ST-06: an auditor cannot execute, another member does not see it, and only the first is recorded', function () {
    requestExecution(loggedIn($this, userIn($this->org->id, 'auditor')), $this->id)->assertStatus(403)->assertJsonPath('code', 'FORBIDDEN');

    expect(executionDenials($this->id))->toBe(['FORBIDDEN']);

    requestExecution(loggedIn($this, userIn($this->org->id)), $this->id)->assertStatus(404);

    expect(executionDenials($this->id))->toBe(['FORBIDDEN'])->and(executionRow($this->id))->toBeNull();
});

it('AUTH-LOCK-03: a locked owner can execute', function () {
    $client = loggedIn($this, $this->owner);
    DB::table('users')->where('id', $this->owner->id)->update(['locked_until' => now()->addMinutes(15)]);

    requestExecution($client, $this->id)->assertStatus(202);
});

it('refuses with 403 when the user was deactivated or demoted after the request began, and records it', function (array $change) {
    $stale = $this->admin->fresh();
    DB::table('users')->where('id', $this->admin->id)->update($change);

    $attempt = fn () => app(OrganizationContext::class)->run($this->org->id, fn () => app(ExecutionService::class)->request($stale, Workflow::query()->findOrFail($this->id), A_KEY));

    try {
        $attempt();
        $this->fail('It was accepted.');
    } catch (AuthorizationException $exception) {
        expect($exception->status())->not->toBe(404);
    }

    expect(executionRow($this->id))->toBeNull()->and(executionDenials($this->id))->toBe(['FORBIDDEN']);
})->with([[['is_active' => false]], [['role' => 'member']]]);

// ---- The checks of §10 --------------------------------------------------------------------------------

it('ST-08: refuses what is not approved, and records it', function (string $status) {
    DB::table('workflows')->where('id', $this->id)->update(['status' => $status]);

    requestExecution(loggedIn($this, $this->owner), $this->id)->assertStatus(409)->assertJsonPath('code', 'APPROVAL_NOT_VALID');

    expect(executionRow($this->id))->toBeNull()->and(executionDenials($this->id))->toBe(['APPROVAL_NOT_VALID']);
})->with(['draft', 'pending', 'rejected', 'running', 'completed', 'failed']);

it('ST-08: refuses when the approval is for an earlier revision', function () {
    $workflow = Workflow::query()->withoutGlobalScopes()->findOrFail($this->id);
    $revision = insertRevision(appDb(), $workflow, ['revision_no' => 2]);
    DB::table('workflows')->where('id', $this->id)->update(['current_revision_id' => $revision]);

    requestExecution(loggedIn($this, $this->owner), $this->id)->assertStatus(409)->assertJsonPath('code', 'APPROVAL_NOT_VALID');
});

it('ST-08: a rejection is not an approval', function () {
    $id = runnablePlan($this->owner, $this->admin);
    $revision = DB::table('workflow_revisions')->where('workflow_id', $id)->value('id');
    $workflow = Workflow::query()->withoutGlobalScopes()->findOrFail($id);
    $second = insertRevision(appDb(), $workflow, ['revision_no' => 2]);
    insertApproval(appDb(), $workflow, $second, $this->admin->id, ['decision' => 'rejected']);
    DB::table('workflows')->where('id', $id)->update(['current_revision_id' => $second]);

    expect($revision)->not->toBe($second);
    requestExecution(loggedIn($this, $this->owner), $id)->assertStatus(409)->assertJsonPath('code', 'APPROVAL_NOT_VALID');
});

it('ST-37: an approval by the creator is not valid, whatever got it into the table', function () {
    $workflow = Workflow::query()->withoutGlobalScopes()->findOrFail($this->id);
    $client = loggedIn($this, $this->owner);

    // The trigger stops such a row, so the check is made on the rule itself.
    $refusal = app(OrganizationContext::class)->run($this->org->id, fn () => ExecutionVerifier::refusal(
        (clone $workflow)->forceFill(['created_by' => $this->admin->id]),
        WorkflowRevision::query()->findOrFail($workflow->current_revision_id),
        Approval::query()->where('workflow_id', $this->id)->sole(),
        WorkflowTask::query()->where('workflow_id', $this->id)->orderBy('position')->get(),
    ));

    expect($refusal)->toBe('APPROVAL_NOT_VALID');

    requestExecution($client, $this->id)->assertStatus(202);
});

it('ST-08: an approval of another revision, or of another hash, is not valid', function () {
    $first = app(OrganizationContext::class)->run($this->org->id, fn () => Approval::query()->where('workflow_id', $this->id)->sole());
    $current = reviseWith($this->id, $this->admin);

    $check = fn (Approval $approval) => app(OrganizationContext::class)->run($this->org->id, fn () => ExecutionVerifier::refusal(
        Workflow::query()->findOrFail($this->id),
        WorkflowRevision::query()->findOrFail($current),
        $approval,
        WorkflowTask::query()->where('workflow_id', $this->id)->orderBy('position')->get(),
    ));
    $valid = app(OrganizationContext::class)->run($this->org->id, fn () => Approval::query()->where('workflow_revision_id', $current)->sole());

    expect($check($valid))->toBeNull()
        ->and($check($first))->toBe('APPROVAL_NOT_VALID')
        ->and($check((clone $valid)->forceFill(['plan_hash' => str_repeat('b', 64)])))->toBe('APPROVAL_NOT_VALID')
        ->and($check((clone $valid)->forceFill(['workflow_revision_id' => $first->workflow_revision_id])))->toBe('APPROVAL_NOT_VALID');
});

it('refuses a revision the scan stopped', function () {
    reviseWith($this->id, $this->admin, [
        'scan_id' => insertScan(appDb(), $this->org->id, ['decision' => 'block', 'block_reason' => 'SECRET_DETECTED', 'target_type' => 'revision']),
        'scan_decision' => 'block',
    ]);

    requestExecution(loggedIn($this, $this->owner), $this->id)->assertStatus(409)->assertJsonPath('code', 'SCAN_BLOCKED');

    expect(executionDenials($this->id))->toBe(['SCAN_BLOCKED']);
});

it('runs a revision the scan warned about', function () {
    reviseWith($this->id, $this->admin, [
        'scan_id' => insertScan(appDb(), $this->org->id, ['decision' => 'warn', 'target_type' => 'revision']),
        'scan_decision' => 'warn',
    ]);

    requestExecution(loggedIn($this, $this->owner), $this->id)->assertStatus(202);
});

it('refuses an action forbidden as stored or by the catalog now', function (array $change) {
    $client = loggedIn($this, $this->owner);
    DB::table('workflow_tasks')->where('workflow_id', $this->id)->update($change);

    $client->send('POST', EXECUTION_WORKFLOWS.$this->id.'/execute', null, ['HTTP_IDEMPOTENCY_KEY' => A_KEY])
        ->assertStatus(409)->assertJsonPath('code', 'POLICY_VIOLATION');

    expect(executionDenials($this->id))->toBe(['POLICY_FORBIDDEN']);
})->with([[['policy_decision' => 'forbidden']], [['action_type' => 'shell.exec']]]);

it('refuses a plan approved under another version of the policy, and says so in the record', function () {
    reviseWith($this->id, $this->admin, ['policy_version' => '2020.1.1']);

    requestExecution(loggedIn($this, $this->owner), $this->id)->assertStatus(409)->assertJsonPath('code', 'POLICY_VIOLATION');

    expect(executionDenials($this->id))->toBe(['POLICY_VERSION_CHANGED']);
});

it('refuses tasks that are no longer what was approved', function () {
    $client = loggedIn($this, $this->owner);
    DB::table('workflow_tasks')->where('workflow_id', $this->id)->update(['title' => '書き換えられた']);

    requestExecution($client, $this->id)->assertStatus(409)->assertJsonPath('code', 'PLAN_HASH_MISMATCH');

    expect(executionDenials($this->id))->toBe(['PLAN_HASH_MISMATCH']);
});

it('ST-09: an edit after the approval takes it away', function () {
    $client = loggedIn($this, $this->owner);
    $task = (string) DB::table('workflow_tasks')->where('workflow_id', $this->id)->orderBy('position')->value('id');
    $client->send('PUT', EXECUTION_WORKFLOWS.$this->id.'/tasks/'.$task, [
        'title' => '編集', 'description' => 'D', 'action_type' => 'text.analyze', 'steps' => ['S'], 'priority' => 'low', 'target_data' => 'T', 'impact_summary' => 'I',
    ], ['HTTP_IF_MATCH' => '"1"'])->assertOk();

    requestExecution($client, $this->id)->assertStatus(409)->assertJsonPath('code', 'APPROVAL_NOT_VALID');
});

it('cannot edit a running workflow', function () {
    $client = loggedIn($this, $this->owner);
    requestExecution($client, $this->id)->assertStatus(202);
    $task = (string) DB::table('workflow_tasks')->where('workflow_id', $this->id)->orderBy('position')->value('id');

    $client->send('PUT', EXECUTION_WORKFLOWS.$this->id.'/tasks/'.$task, [
        'title' => '編集', 'description' => 'D', 'action_type' => 'text.analyze', 'steps' => ['S'], 'priority' => 'low', 'target_data' => 'T', 'impact_summary' => 'I',
    ], ['HTTP_IF_MATCH' => '"1"'])->assertStatus(409);
});

// ---- ST-22: one execution -------------------------------------------------------------------------------

it('ST-22: the same key gets the same execution back, with nothing new', function () {
    $client = loggedIn($this, $this->owner);

    $first = requestExecution($client, $this->id)->assertStatus(202);
    $second = requestExecution($client, $this->id)->assertStatus(202);

    expect($second->json('data.execution_id'))->toBe($first->json('data.execution_id'))
        ->and(DB::table('workflow_executions')->where('workflow_id', $this->id)->count())->toBe(1)
        ->and(executionAudit($this->id, 'execution.started'))->toHaveCount(1)
        ->and(DB::table('jobs')->where('queue', 'execution')->count())->toBe(1)
        ->and(executionDenials($this->id))->toBe([]);
});

it('ST-22: the same key after it has finished still gets the first answer', function () {
    $client = loggedIn($this, $this->owner);
    $first = requestExecution($client, $this->id)->assertStatus(202);
    runJob($first->json('data.execution_id'), $this->org->id);

    requestExecution($client, $this->id)->assertStatus(202)
        ->assertJsonPath('data.execution_id', $first->json('data.execution_id'))
        ->assertJsonPath('data.status', 'completed');
});

it('ST-22: another key cannot use the approval again, however it ended', function (string $end) {
    $client = loggedIn($this, $this->owner);
    $first = requestExecution($client, $this->id)->assertStatus(202);

    match ($end) {
        'waiting' => null,
        'completed' => runJob($first->json('data.execution_id'), $this->org->id),
        'failed' => app(OrganizationContext::class)->run($this->org->id, fn () => app(ExecutionProcessor::class)->fail($first->json('data.execution_id'), ExecutionProcessor::ERROR_FAILED)),
    };

    requestExecution($client, $this->id, 'key-2')->assertStatus(409)->assertJsonPath('code', 'EXECUTION_ALREADY_EXISTS');

    expect(DB::table('workflow_executions')->where('workflow_id', $this->id)->count())->toBe(1)
        ->and(executionDenials($this->id))->toBe(['EXECUTION_ALREADY_EXISTS']);
})->with(['waiting', 'completed', 'failed']);

it('refuses a key used on another workflow, by another person, or for an earlier approval', function (string $case) {
    $client = loggedIn($this, $this->owner);
    $first = requestExecution($client, $this->id)->assertStatus(202);

    $response = match ($case) {
        'workflow' => requestExecution($client, runnablePlan($this->owner, $this->admin)),
        'person' => requestExecution(loggedIn($this, $this->admin), $this->id),
        'approval' => (function () use ($client, $first) {
            app(OrganizationContext::class)->run($this->org->id, fn () => app(ExecutionProcessor::class)->fail($first->json('data.execution_id'), ExecutionProcessor::ERROR_FAILED));
            reviseWith($this->id, $this->admin);
            DB::table('workflows')->where('id', $this->id)->update(['status' => 'approved']);

            return requestExecution($client, $this->id);
        })(),
    };

    $response->assertStatus(422)->assertJsonPath('code', 'IDEMPOTENCY_KEY_REUSED');

    expect($response->getContent())->not->toContain($first->json('data.execution_id'))
        ->and(DB::table('workflow_executions')->where('id', '!=', $first->json('data.execution_id'))->where('idempotency_key', A_KEY)->count())->toBe(0);
})->with(['workflow', 'person', 'approval']);

it('lets the same key mean different things in different organizations', function () {
    requestExecution(loggedIn($this, $this->owner), $this->id)->assertStatus(202);

    $org = Organization::factory()->create();
    $owner = userIn($org->id);

    requestExecution(loggedIn($this, $owner), runnablePlan($owner, userIn($org->id, 'admin')))->assertStatus(202);
});

// ---- Running ------------------------------------------------------------------------------------------------

it('runs the approved plan, completes it, records it and keeps no task text', function () {
    $marker = (string) DB::table('workflow_tasks')->where('workflow_id', $this->id)->value('title');
    $execution = requestExecution(loggedIn($this, $this->owner), $this->id)->json('data.execution_id');

    runJob($execution, $this->org->id);

    $row = executionRow($this->id);
    $result = json_decode((string) $row->result, true);

    expect($row->status)->toBe('completed')
        ->and($row->started_at)->not->toBeNull()
        ->and($row->finished_at)->not->toBeNull()
        ->and($row->error_code)->toBeNull()
        ->and(workflowStatus($this->id))->toBe('completed')
        ->and($result['simulated'])->toBeTrue()
        ->and($result['tasks'])->toHaveCount(DB::table('workflow_tasks')->where('workflow_id', $this->id)->count())
        ->and(array_keys($result['tasks'][0]))->toEqualCanonicalizing(['position', 'action_type', 'summary'])
        ->and((string) $row->result)->not->toContain($marker);

    $audit = executionAudit($this->id, 'execution.completed')->sole();

    expect($audit->actor_type)->toBe('system')
        ->and(json_decode((string) $audit->metadata, true))->toBe(['execution_id' => $execution]);
});

it('does nothing when the job comes back: a second run cannot happen', function () {
    $execution = requestExecution(loggedIn($this, $this->owner), $this->id)->json('data.execution_id');

    runJob($execution, $this->org->id);
    $after = executionRow($this->id);
    runJob($execution, $this->org->id);

    expect(executionRow($this->id))->toEqual($after)->and(executionAudit($this->id, 'execution.completed'))->toHaveCount(1);
});

it('runs what was approved rather than the task rows', function () {
    $execution = requestExecution(loggedIn($this, $this->owner), $this->id)->json('data.execution_id');
    $approved = json_decode((string) DB::table('workflow_revisions')->where('workflow_id', $this->id)->value('plan_snapshot'), true)['tasks'][0]['action_type'];
    DB::table('workflow_tasks')->where('workflow_id', $this->id)->update(['action_type' => 'task.create']);

    runJob($execution, $this->org->id);

    expect(json_decode((string) executionRow($this->id)->result, true)['tasks'][0]['action_type'])->toBe($approved)
        ->and($approved)->not->toBe('task.create');
});

it('fails, and does not run, when the requester was deactivated meanwhile', function () {
    $execution = requestExecution(loggedIn($this, $this->owner), $this->id)->json('data.execution_id');
    DB::table('users')->where('id', $this->owner->id)->update(['is_active' => false]);

    runJob($execution, $this->org->id);

    expect(executionRow($this->id)->error_code)->toBe('USER_INACTIVE')
        ->and(executionRow($this->id)->result)->toBeNull()
        ->and(workflowStatus($this->id))->toBe('failed');
});

it('fails, and does not run, when the plan is not the approved one any more', function (string $case) {
    $execution = requestExecution(loggedIn($this, $this->owner), $this->id)->json('data.execution_id');

    match ($case) {
        'state' => DB::table('workflows')->where('id', $this->id)->update(['status' => 'running', 'current_revision_id' => insertRevision(appDb(), Workflow::query()->withoutGlobalScopes()->findOrFail($this->id), ['revision_no' => 2])]),
    };

    runJob($execution, $this->org->id);

    expect(executionRow($this->id)->error_code)->toBe('EXECUTION_PLAN_CHANGED')
        ->and(executionRow($this->id)->result)->toBeNull();
})->with(['state']);

it('fails, and does not run, when the stored plan is not what was approved', function (string $case) {
    $workflow = Workflow::query()->withoutGlobalScopes()->findOrFail($this->id);
    $good = DB::table('workflow_revisions')->where('workflow_id', $this->id)->first();
    $revision = insertRevision(appDb(), $workflow, [
        'revision_no' => 2,
        'plan_snapshot' => $case === 'the snapshot' ? '{}' : $good->plan_snapshot,
        'plan_hash' => $good->plan_hash,
    ]);
    $approval = insertApproval(appDb(), $workflow, $revision, $this->admin->id, ['plan_hash' => $case === 'the approval' ? str_repeat('b', 64) : $good->plan_hash]);
    DB::table('workflows')->where('id', $this->id)->update(['status' => 'running', 'current_revision_id' => $revision]);
    $execution = insertExecution(appDb(), $workflow, $revision, $approval);

    runJob($execution, $this->org->id);

    expect(DB::table('workflow_executions')->where('id', $execution)->value('error_code'))->toBe('EXECUTION_PLAN_CHANGED')
        ->and(DB::table('workflow_executions')->where('id', $execution)->value('result'))->toBeNull();
})->with(['the snapshot', 'the approval']);

it('has a handler for every allowed action and none for a forbidden one', function () {
    foreach (ActionCatalog::types() as $type) {
        $allowed = ActionCatalog::decision($type) === PolicyDecision::Allowed;

        expect(ExecutionSimulator::run($type) !== null)->toBe($allowed, $type);
    }

    expect(ExecutionSimulator::run('anything.else'))->toBeNull();
});

it('leaves no execution behind when it cannot be recorded', function () {
    $client = loggedIn($this, $this->owner);
    useAuditWriter(new FailingAuditWriter('53100', 'could not extend file: No space left on device'));

    requestExecution($client, $this->id)->assertStatus(503);

    expect(executionRow($this->id))->toBeNull()
        ->and(workflowStatus($this->id))->toBe('approved')
        ->and(DB::table('jobs')->where('queue', 'execution')->count())->toBe(0);
});

it('still refuses, with the same answer, when a denial cannot be recorded', function () {
    DB::table('workflows')->where('id', $this->id)->update(['status' => 'draft']);
    $client = loggedIn($this, $this->owner);
    $auditor = loggedIn($this, userIn($this->org->id, 'auditor'));
    useAuditWriter(new FailingAuditWriter('53100', 'could not extend file: No space left on device'));

    requestExecution($client, $this->id)->assertStatus(409)->assertJsonPath('code', 'APPROVAL_NOT_VALID');
    requestExecution($auditor, $this->id)->assertStatus(403)->assertJsonPath('code', 'FORBIDDEN');
});

it('does not start while the audit log is known to be unavailable, but still gives the refusal', function () {
    $client = loggedIn($this, $this->owner);
    $writer = app(AuditWriter::class);
    useAuditWriter(new FailingAuditWriter('53100', 'could not extend file: No space left on device'));
    app(AuditLogger::class)->recordAfterTransaction(AuditEntry::system(AuditEventType::AnalysisFailed, $this->owner, 'failure'), 'test');
    useAuditWriter($writer);

    requestExecution($client, $this->id)->assertStatus(503);

    expect(executionRow($this->id))->toBeNull()->and(workflowStatus($this->id))->toBe('approved');

    DB::table('workflows')->where('id', $this->id)->update(['status' => 'draft']);

    requestExecution($client, $this->id)->assertStatus(409)->assertJsonPath('code', 'APPROVAL_NOT_VALID');
});

it('fails the run instead of leaving it hanging when completing it cannot be recorded', function () {
    $execution = requestExecution(loggedIn($this, $this->owner), $this->id)->json('data.execution_id');
    useAuditWriter(new FailingAuditWriter('53100', 'could not extend file: No space left on device'));

    runJob($execution, $this->org->id);

    expect(executionRow($this->id)->status)->toBe('failed')
        ->and(executionRow($this->id)->error_code)->toBe('EXECUTION_FAILED')
        ->and(executionRow($this->id)->result)->toBeNull()
        ->and(workflowStatus($this->id))->toBe('failed');
});

it('limits the requests, which also limits how many denials can be written', function () {
    $client = loggedIn($this, userIn($this->org->id, 'auditor'));

    foreach (range(1, 30) as $ignored) {
        requestExecution($client, $this->id)->assertStatus(403);
    }

    requestExecution($client, $this->id)->assertStatus(429)->assertJsonPath('code', 'RATE_LIMITED');

    expect(executionDenials($this->id))->toHaveCount(30);
});

// ---- ST-33: what a dead worker leaves behind ---------------------------------------------------------------

it('ST-33: gives up on a run with no heartbeat and on a job nobody took, in every organization', function () {
    $execution = requestExecution(loggedIn($this, $this->owner), $this->id)->json('data.execution_id');
    DB::table('workflow_executions')->where('id', $execution)->update(['status' => 'running', 'heartbeat_at' => now()->subSeconds(ExecutionsReapStaleCommand::RUNNING_LIMIT_SECONDS + 1)]);

    $otherOrg = Organization::factory()->create();
    $otherOwner = userIn($otherOrg->id);
    $other = runnablePlan($otherOwner, userIn($otherOrg->id, 'admin'));
    $queued = requestExecution(loggedIn($this, $otherOwner), $other)->json('data.execution_id');
    expect($queued)->toBeString();

    // Nobody took it, and its created_at cannot be changed by the application.
    $this->travel(ExecutionsReapStaleCommand::QUEUED_LIMIT_SECONDS + 1)->seconds();

    expect(Artisan::call('executions:reap-stale'))->toBe(0);

    foreach ([$this->id, $other] as $id) {
        expect(executionRow($id)->status)->toBe('failed')
            ->and(executionRow($id)->error_code)->toBe('EXECUTION_STALE')
            ->and(workflowStatus($id))->toBe('failed')
            ->and(json_decode((string) executionAudit($id, 'execution.failed')->sole()->metadata, true)['reason_code'])->toBe('EXECUTION_STALE');
    }
});

it('ST-33: leaves alone what is still within its time', function () {
    $execution = requestExecution(loggedIn($this, $this->owner), $this->id)->json('data.execution_id');
    DB::table('workflow_executions')->where('id', $execution)->update(['status' => 'running', 'heartbeat_at' => now()->subSeconds(ExecutionsReapStaleCommand::RUNNING_LIMIT_SECONDS - 30)]);

    Artisan::call('executions:reap-stale');

    expect(executionRow($this->id)->status)->toBe('running')->and(workflowStatus($this->id))->toBe('running');
});

it('ST-33: a job that comes back after being given up on changes nothing', function () {
    $execution = requestExecution(loggedIn($this, $this->owner), $this->id)->json('data.execution_id');
    DB::table('workflow_executions')->where('id', $execution)->update(['status' => 'running', 'heartbeat_at' => now()->subHour()]);
    Artisan::call('executions:reap-stale');
    $after = executionRow($this->id);

    runJob($execution, $this->org->id);
    (new ExecuteWorkflowJob($execution, $this->org->id))->failed(null);

    expect(executionRow($this->id))->toEqual($after)->and(executionAudit($this->id, 'execution.failed'))->toHaveCount(1);
});

it('ST-33: a failure cannot undo a result', function () {
    $execution = requestExecution(loggedIn($this, $this->owner), $this->id)->json('data.execution_id');
    runJob($execution, $this->org->id);

    (new ExecuteWorkflowJob($execution, $this->org->id))->failed(null);

    expect(executionRow($this->id)->status)->toBe('completed')->and(workflowStatus($this->id))->toBe('completed');
});

it('ST-33: after a failure it takes reopening, submitting and approving again', function () {
    $owner = loggedIn($this, $this->owner);
    $execution = requestExecution($owner, $this->id)->json('data.execution_id');
    (new ExecuteWorkflowJob($execution, $this->org->id))->failed(null);

    requestExecution($owner, $this->id, 'key-2')->assertStatus(409)->assertJsonPath('code', 'EXECUTION_ALREADY_EXISTS');
    $owner->send('POST', EXECUTION_WORKFLOWS.$this->id.'/reopen')->assertOk()->assertJsonPath('data.status', 'draft');
    requestExecution($owner, $this->id, 'key-2')->assertStatus(409)->assertJsonPath('code', 'APPROVAL_NOT_VALID');
    $owner->send('POST', EXECUTION_WORKFLOWS.$this->id.'/submit')->assertOk();

    $revision = DB::table('workflow_revisions')->where('workflow_id', $this->id)->orderByDesc('revision_no')->first();
    loggedIn($this, $this->admin)->send('POST', EXECUTION_WORKFLOWS.$this->id.'/approve', ['revision_no' => $revision->revision_no, 'plan_hash' => $revision->plan_hash, 'acknowledged_risks' => false])->assertOk();

    requestExecution($owner, $this->id, 'key-2')->assertStatus(202);
});

it('keeps the time limits in the right order', function () {
    $job = new ExecuteWorkflowJob('a', 'b');

    expect($job->tries)->toBe(1)
        ->and($job->queue)->toBe('execution')
        ->and(config('queue.connections.database.retry_after'))->toBeGreaterThan($job->timeout)
        ->and(ExecutionsReapStaleCommand::RUNNING_LIMIT_SECONDS)->toBeGreaterThan(config('queue.connections.database.retry_after'));
});

it('does not use ShouldBeUnique: the row is what decides', function () {
    expect(class_implements(ExecuteWorkflowJob::class))->not->toHaveKey(ShouldBeUnique::class);
});

it('is on the schedule', function () {
    expect(collect(app(Schedule::class)->events())->map->description->all())->toContain('executions:reap-stale');
    expect(Route::has('workflows.execute'))->toBeTrue();
});

// ---- Reading -------------------------------------------------------------------------------------------------

it('shows the history to those who may see the workflow', function (string $who, int $status) {
    $execution = requestExecution(loggedIn($this, $this->owner), $this->id)->json('data.execution_id');
    runJob($execution, $this->org->id);
    $user = match ($who) {
        'owner' => $this->owner,
        'admin' => $this->admin,
        'auditor' => userIn($this->org->id, 'auditor'),
        'other member' => userIn($this->org->id),
    };

    $response = loggedIn($this, $user)->send('GET', EXECUTION_WORKFLOWS.$this->id.'/executions')->assertStatus($status);

    if ($status === 200) {
        expect($response->json('data.0.id'))->toBe($execution)
            ->and($response->json('data.0.status'))->toBe('completed')
            ->and($response->json('data.0.revision_no'))->toBe(1)
            ->and($response->json('data.0.result.simulated'))->toBeTrue()
            ->and($response->json('data.0'))->not->toHaveKey('idempotency_key');
    }
})->with([['owner', 200], ['admin', 200], ['auditor', 200], ['other member', 404]]);

it('says who can execute', function () {
    $owner = loggedIn($this, $this->owner);

    $owner->send('GET', EXECUTION_WORKFLOWS.$this->id)->assertOk()->assertJsonPath('data.can_execute', true);
    loggedIn($this, userIn($this->org->id, 'auditor'))->send('GET', EXECUTION_WORKFLOWS.$this->id)->assertOk()->assertJsonPath('data.can_execute', false);

    DB::table('workflows')->where('id', $this->id)->update(['status' => 'draft']);

    $owner->send('GET', EXECUTION_WORKFLOWS.$this->id)->assertOk()->assertJsonPath('data.can_execute', false);
});

it('counts a completed execution on the dashboard', function () {
    $owner = loggedIn($this, $this->owner);
    $execution = requestExecution($owner, $this->id)->json('data.execution_id');
    runJob($execution, $this->org->id);

    $owner->send('GET', '/api/v1/dashboard/summary')->assertOk()->assertJsonPath('data.executed', 1);
});
