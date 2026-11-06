<?php

use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Domain\Workflow\AnalysisProcessor;
use App\Domain\Workflow\PlanHasher;
use App\Jobs\AnalyzeWorkflowJob;
use App\Models\AiAnalysisRequest;
use App\Models\Organization;
use App\Models\User;
use App\Support\Organization\OrganizationContext;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\TestResponse;
use Tests\Support\FailingAuditWriter;
use Tests\Support\SpaClient;

/*
| docs/api-design.md §3.4. ST-12, ST-17, and every edit committing with its revision and audit record.
*/

uses(DatabaseTransactions::class);

const WORKFLOWS = '/api/v1/workflows';

function generatedWorkflow(User $user): string
{
    $analysis = app(OrganizationContext::class)->run($user->organization_id, function () use ($user) {
        $analysis = new AiAnalysisRequest;
        $analysis->forceFill(['user_id' => $user->id, 'status' => 'queued', 'input_char_count' => 1, 'input_scan_id' => insertScan(appDb(), $user->organization_id)])->save();

        return $analysis;
    });

    (new AnalyzeWorkflowJob($analysis->id, $analysis->organization_id))->handle(app(AnalysisProcessor::class), app(OrganizationContext::class));

    return (string) DB::table('ai_analysis_requests')->where('id', $analysis->id)->value('workflow_id');
}

function taskBody(array $overrides = []): array
{
    return [
        'title' => '編集後のタイトル',
        'description' => '編集後の説明',
        'action_type' => 'report.draft',
        'steps' => ['手順1', '手順2'],
        'priority' => 'high',
        'target_data' => '対象',
        'impact_summary' => '影響',
        ...$overrides,
    ];
}

function ifMatch(int|string $revision): array
{
    return ['HTTP_IF_MATCH' => '"'.$revision.'"'];
}

function firstTaskId(string $workflowId): string
{
    return (string) DB::table('workflow_tasks')->where('workflow_id', $workflowId)->orderBy('position')->value('id');
}

function currentHash(string $workflowId): string
{
    return (string) DB::table('workflow_revisions')->where('workflow_id', $workflowId)->orderByDesc('revision_no')->value('plan_hash');
}

function putTask(SpaClient $client, string $id, array $body = [], int|string $revision = 1): TestResponse
{
    return $client->send('PUT', WORKFLOWS.'/'.$id.'/tasks/'.firstTaskId($id), taskBody($body), ifMatch($revision));
}

beforeEach(function () {
    $this->org = Organization::factory()->create();
    $this->member = userIn($this->org->id);
    $this->id = generatedWorkflow($this->member);
});

// ---- Reading ------------------------------------------------------------------------------------

it('lists a member\'s own workflows only', function () {
    generatedWorkflow(userIn($this->org->id));

    $response = loggedIn($this, $this->member)->send('GET', WORKFLOWS)->assertOk();

    expect(array_column($response->json('data'), 'id'))->toBe([$this->id])
        ->and($response->json('data.0.revision_no'))->toBe(1)
        ->and($response->json('data.0.status'))->toBe('draft')
        ->and($response->json('data.0.created_by.id'))->toBe($this->member->id);
});

it('lists the whole organization for an admin or auditor, and nothing from another', function (string $role) {
    $other = generatedWorkflow(userIn($this->org->id));
    generatedWorkflow(userIn(Organization::factory()->create()->id));

    $ids = array_column(loggedIn($this, userIn($this->org->id, $role))->send('GET', WORKFLOWS)->assertOk()->json('data'), 'id');

    sort($ids);
    $expected = [$this->id, $other];
    sort($expected);

    expect($ids)->toBe($expected);
})->with(['admin', 'auditor']);

it('filters by status, and pages with a cursor', function () {
    generatedWorkflow($this->member);
    generatedWorkflow($this->member);
    $client = loggedIn($this, $this->member);

    expect($client->send('GET', WORKFLOWS.'?status=pending')->assertOk()->json('data'))->toBe([]);

    $first = $client->send('GET', WORKFLOWS.'?limit=2')->assertOk();
    $next = $first->json('meta.next_cursor');

    expect($first->json('data'))->toHaveCount(2)->and($next)->not->toBeNull();

    $second = $client->send('GET', WORKFLOWS.'?limit=2&cursor='.$next)->assertOk();

    expect($second->json('data'))->toHaveCount(1)
        ->and(array_intersect(array_column($first->json('data'), 'id'), array_column($second->json('data'), 'id')))->toBe([]);
});

it('refuses list parameters outside the design', function (string $query) {
    loggedIn($this, $this->member)->send('GET', WORKFLOWS.$query)->assertStatus(422);
})->with(['?status=unknown', '?limit=0', '?limit=101', '?limit=x', '?other=1']);

it('shows the tasks, the revision and what the scan said', function () {
    $response = loggedIn($this, $this->member)->send('GET', WORKFLOWS.'/'.$this->id)->assertOk();

    $response->assertJsonPath('data.status', 'draft')
        ->assertJsonPath('data.current_revision.no', 1)
        ->assertJsonPath('data.current_revision.plan_hash', currentHash($this->id))
        ->assertJsonPath('data.scan.status', 'scanned')
        ->assertJsonPath('data.scan.decision', 'allow')
        ->assertJsonPath('data.can_edit', true)
        ->assertJsonPath('data.tasks.0.position', 1)
        ->assertJsonPath('data.tasks.0.derived_permissions', ['ai.text.read'])
        ->assertJsonMissingPath('data.tasks.0.ai_claimed_permissions')
        ->assertJsonMissingPath('data.source_input_masked');

    expect($response->json('data.scan.limitations_notice'))->not->toBeEmpty();
});

it('tells an admin who may not edit, and a member with a running workflow', function () {
    loggedIn($this, userIn($this->org->id, 'admin'))->send('GET', WORKFLOWS.'/'.$this->id)->assertJsonPath('data.can_edit', false);

    DB::table('workflows')->where('id', $this->id)->update(['status' => 'running']);

    loggedIn($this, $this->member, ip: '203.0.113.20')->send('GET', WORKFLOWS.'/'.$this->id)->assertJsonPath('data.can_edit', false);
});

it('gives the history without the content of the plans', function () {
    $client = loggedIn($this, $this->member);
    putTask($client, $this->id)->assertOk();

    $response = $client->send('GET', WORKFLOWS.'/'.$this->id.'/history')->assertOk();

    expect(array_column($response->json('data.revisions'), 'revision_no'))->toBe([2, 1])
        ->and(array_column($response->json('data.revisions'), 'change_type'))->toBe(['user_edit', 'ai_generated'])
        ->and($response->json('data.approvals'))->toBe([])
        ->and($response->json('data.executions'))->toBe([])
        ->and($response->getContent())->not->toContain('plan_snapshot')
        ->not->toContain('編集後の説明');
});

// ---- Editing a task -----------------------------------------------------------------------------

it('makes a new revision for an edit, with a new hash and the server\'s permissions', function () {
    $before = currentHash($this->id);

    $response = putTask(loggedIn($this, $this->member), $this->id)->assertOk();

    $response->assertJsonPath('data.current_revision.no', 2)
        ->assertJsonPath('data.tasks.0.title', '編集後のタイトル')
        ->assertJsonPath('data.tasks.0.derived_permissions', ['ai.text.read', 'report.draft.write'])
        ->assertJsonPath('data.tasks.0.policy_decision', 'allowed');

    $revision = DB::table('workflow_revisions')->where('workflow_id', $this->id)->where('revision_no', 2)->first();

    expect($revision->plan_hash)->not->toBe($before)
        ->and($revision->change_type)->toBe('user_edit')
        ->and($revision->created_by)->toBe($this->member->id)
        ->and($revision->scan_decision)->toBe('allow')
        ->and($revision->scan_id)->not->toBeNull()
        ->and(PlanHasher::matches(json_decode($revision->plan_snapshot, true), $revision->plan_hash))->toBeTrue()
        ->and(DB::table('workflows')->where('id', $this->id)->value('current_revision_id'))->toBe($revision->id);
});

it('keeps the old revision exactly as it was', function () {
    $old = DB::table('workflow_revisions')->where('workflow_id', $this->id)->first();

    putTask(loggedIn($this, $this->member), $this->id)->assertOk();

    expect(DB::table('workflow_revisions')->where('id', $old->id)->first())->toEqual($old);
});

it('ST-09: an edit after approval goes back to draft', function (string $status) {
    DB::table('workflows')->where('id', $this->id)->update(['status' => $status]);

    putTask(loggedIn($this, $this->member), $this->id)->assertOk()->assertJsonPath('data.status', 'draft');
})->with(['pending', 'approved']);

it('refuses to edit a workflow in a state that does not allow it', function (string $status) {
    DB::table('workflows')->where('id', $this->id)->update(['status' => $status]);

    putTask(loggedIn($this, $this->member), $this->id)
        ->assertStatus(409)
        ->assertJsonPath('code', 'WORKFLOW_INVALID_STATE');

    expect(DB::table('workflow_revisions')->where('workflow_id', $this->id)->count())->toBe(1);
})->with(['running', 'completed', 'rejected', 'failed']);

it('ST-17: changing to a forbidden action is saved and marked, by the server', function () {
    putTask(loggedIn($this, $this->member), $this->id, ['action_type' => 'shell.exec'])
        ->assertOk()
        ->assertJsonPath('data.tasks.0.policy_decision', 'forbidden')
        ->assertJsonPath('data.tasks.0.derived_permissions', ['system.shell']);
});

it('does not accept what only the server decides', function (array $body) {
    $client = loggedIn($this, $this->member);

    $client->send('PUT', WORKFLOWS.'/'.$this->id.'/tasks/'.firstTaskId($this->id), taskBody($body), ifMatch(1))
        ->assertStatus(422)
        ->assertJsonPath('code', 'VALIDATION_FAILED');

    expect(DB::table('workflow_revisions')->where('workflow_id', $this->id)->count())->toBe(1);
})->with([
    'permissions' => [['derived_permissions' => ['system.shell']]],
    'decision' => [['policy_decision' => 'allowed']],
    'claimed permissions' => [['ai_claimed_permissions' => []]],
    'position' => [['position' => 3]],
    'organization' => [['organization_id' => 'x']],
    'an unknown action' => [['action_type' => 'payment.transfer']],
    'an action in another case' => [['action_type' => 'TEXT.ANALYZE']],
    'an unknown priority' => [['priority' => 'urgent']],
    'a title too long' => [['title' => str_repeat('あ', 101)]],
    'a description too long' => [['description' => str_repeat('あ', 1001)]],
    'a target too long' => [['target_data' => str_repeat('あ', 501)]],
    'an impact too long' => [['impact_summary' => str_repeat('あ', 1001)]],
    'a blank title' => [['title' => "\u{3000}\u{200B}"]],
    'a control character' => [['title' => "a\u{0007}b"]],
    'no steps' => [['steps' => []]],
    'too many steps' => [['steps' => array_fill(0, 11, 'x')]],
    'a step too long' => [['steps' => [str_repeat('あ', 201)]]],
    'steps as an object' => [['steps' => ['a' => 'b']]],
    'a number as a step' => [['steps' => [1]]],
]);

it('stores text as typed, so that it can be drawn as text by the screen', function () {
    putTask(loggedIn($this, $this->member), $this->id, ['title' => '<script>alert(1)</script>'])
        ->assertOk()
        ->assertJsonPath('data.tasks.0.title', '<script>alert(1)</script>');
});

// ---- Optimistic locking -------------------------------------------------------------------------

it('requires If-Match', function (array $server) {
    $client = loggedIn($this, $this->member);

    $client->send('PUT', WORKFLOWS.'/'.$this->id.'/tasks/'.firstTaskId($this->id), taskBody(), $server)
        ->assertStatus(428)
        ->assertHeader('Content-Type', 'application/problem+json')
        ->assertJsonPath('code', 'PRECONDITION_REQUIRED');
})->with([
    'missing' => [[]],
    'no quotes' => [['HTTP_IF_MATCH' => '1']],
    'a wildcard' => [['HTTP_IF_MATCH' => '*']],
    'zero' => [['HTTP_IF_MATCH' => '"0"']],
    'not a number' => [['HTTP_IF_MATCH' => '"abc"']],
]);

it('refuses an edit based on an old revision', function () {
    $client = loggedIn($this, $this->member);
    putTask($client, $this->id)->assertOk();

    putTask($client, $this->id, ['title' => '遅れた編集'], 1)
        ->assertStatus(409)
        ->assertJsonPath('code', 'REVISION_CONFLICT');

    expect(DB::table('workflow_tasks')->where('id', firstTaskId($this->id))->value('title'))->toBe('編集後のタイトル');
});

// ---- Adding and deleting ------------------------------------------------------------------------

it('adds a task at the end, with a new revision', function () {
    loggedIn($this, $this->member)->send('POST', WORKFLOWS.'/'.$this->id.'/tasks', taskBody(), ifMatch(1))
        ->assertStatus(201)
        ->assertJsonPath('data.current_revision.no', 2)
        ->assertJsonPath('data.tasks.1.position', 2);
});

it('refuses an eleventh task', function () {
    $client = loggedIn($this, $this->member);

    foreach (range(1, 9) as $i) {
        $client->send('POST', WORKFLOWS.'/'.$this->id.'/tasks', taskBody(), ifMatch($i))->assertStatus(201);
    }

    $client->send('POST', WORKFLOWS.'/'.$this->id.'/tasks', taskBody(), ifMatch(10))
        ->assertStatus(422)
        ->assertJsonPath('code', 'VALIDATION_FAILED');

    expect(DB::table('workflow_tasks')->where('workflow_id', $this->id)->count())->toBe(10);
});

it('deletes a task and closes the gap', function () {
    $client = loggedIn($this, $this->member);
    $client->send('POST', WORKFLOWS.'/'.$this->id.'/tasks', taskBody(['title' => '二番目']), ifMatch(1))->assertStatus(201);
    $client->send('POST', WORKFLOWS.'/'.$this->id.'/tasks', taskBody(['title' => '三番目']), ifMatch(2))->assertStatus(201);

    $response = $client->send('DELETE', WORKFLOWS.'/'.$this->id.'/tasks/'.firstTaskId($this->id), null, ifMatch(3))->assertOk();

    $response->assertJsonPath('data.current_revision.no', 4)
        ->assertJsonPath('data.tasks.0.title', '二番目')
        ->assertJsonPath('data.tasks.0.position', 1)
        ->assertJsonPath('data.tasks.1.position', 2);
});

it('refuses to delete the last task', function () {
    loggedIn($this, $this->member)->send('DELETE', WORKFLOWS.'/'.$this->id.'/tasks/'.firstTaskId($this->id), null, ifMatch(1))
        ->assertStatus(422);

    expect(DB::table('workflow_tasks')->where('workflow_id', $this->id)->count())->toBe(1);
});

it('answers 404 for a task of another workflow, and leaves it alone', function () {
    $other = generatedWorkflow($this->member);
    $task = firstTaskId($other);

    loggedIn($this, $this->member)->send('PUT', WORKFLOWS.'/'.$this->id.'/tasks/'.$task, taskBody(), ifMatch(1))->assertStatus(404);

    expect(DB::table('workflow_tasks')->where('id', $task)->value('title'))->not->toBe('編集後のタイトル');
});

// ---- The title ----------------------------------------------------------------------------------

it('changes the title without a new revision or a change of state', function () {
    DB::table('workflows')->where('id', $this->id)->update(['status' => 'pending']);
    $before = currentHash($this->id);

    loggedIn($this, $this->member)->send('PATCH', WORKFLOWS.'/'.$this->id, ['title' => '新しい題名'], ifMatch(1))
        ->assertOk()
        ->assertJsonPath('data.title', '新しい題名')
        ->assertJsonPath('data.status', 'pending')
        ->assertJsonPath('data.current_revision.no', 1);

    expect(currentHash($this->id))->toBe($before);
});

it('refuses a new title in a state that cannot be edited, or without If-Match, or with another field', function () {
    $client = loggedIn($this, $this->member);

    $client->send('PATCH', WORKFLOWS.'/'.$this->id, ['title' => 'x'])->assertStatus(428);
    $client->send('PATCH', WORKFLOWS.'/'.$this->id, ['title' => 'x', 'status' => 'approved'], ifMatch(1))->assertStatus(422);
    $client->send('PATCH', WORKFLOWS.'/'.$this->id, ['title' => str_repeat('あ', 201)], ifMatch(1))->assertStatus(422);

    DB::table('workflows')->where('id', $this->id)->update(['status' => 'running']);

    $client->send('PATCH', WORKFLOWS.'/'.$this->id, ['title' => 'x'], ifMatch(1))->assertStatus(409);
});

// ---- Who ---------------------------------------------------------------------------------------

it('ST-12, ST-06: who may read and who may change', function (string $role, bool $sameOrganization, int $read, int $write) {
    $user = userIn($sameOrganization ? $this->org->id : Organization::factory()->create()->id, $role);
    $client = loggedIn($this, $user);

    $client->send('GET', WORKFLOWS.'/'.$this->id)->assertStatus($read);
    $client->send('GET', WORKFLOWS.'/'.$this->id.'/history')->assertStatus($read);
    $client->send('PATCH', WORKFLOWS.'/'.$this->id, ['title' => 'x'], ifMatch(1))->assertStatus($write);
    putTask($client, $this->id)->assertStatus($write);
    $client->send('POST', WORKFLOWS.'/'.$this->id.'/tasks', taskBody(), ifMatch(1))->assertStatus($write);
    $client->send('DELETE', WORKFLOWS.'/'.$this->id.'/tasks/'.firstTaskId($this->id), null, ifMatch(1))->assertStatus($write);

    expect(DB::table('workflow_revisions')->where('workflow_id', $this->id)->count())->toBe(1);
})->with([
    'admin' => ['admin', true, 200, 403],
    'auditor' => ['auditor', true, 200, 403],
    'another member' => ['member', true, 404, 404],
    'an admin elsewhere' => ['admin', false, 404, 404],
    'an auditor elsewhere' => ['auditor', false, 404, 404],
    'a member elsewhere' => ['member', false, 404, 404],
]);

it('answers 401 on every route without a session', function (string $method, string $path) {
    spa($this)->csrf()->send($method, str_replace('{id}', $this->id, $path), $method === 'GET' ? null : [])->assertStatus(401);
})->with([
    ['GET', WORKFLOWS],
    ['GET', WORKFLOWS.'/{id}'],
    ['GET', WORKFLOWS.'/{id}/history'],
    ['PATCH', WORKFLOWS.'/{id}'],
    ['POST', WORKFLOWS.'/{id}/tasks'],
]);

// ---- Audit --------------------------------------------------------------------------------------

it('records every change with who, what and no content', function () {
    $client = loggedIn($this, $this->member);
    putTask($client, $this->id, ['title' => '内容に含まれる語'])->assertOk();
    $client->send('PATCH', WORKFLOWS.'/'.$this->id, ['title' => '題名に含まれる語'], ifMatch(2))->assertOk();

    $events = DB::table('audit_logs')->where('event_type', 'workflow.updated')->orderBy('chain_seq')->get();

    expect($events)->toHaveCount(2)
        ->and(json_decode($events[0]->metadata, true))->toBe(['change' => 'task', 'revision_no' => 2])
        ->and(json_decode($events[1]->metadata, true))->toBe(['change' => 'title', 'revision_no' => 2])
        ->and($events[0]->actor_user_id)->toBe($this->member->id)
        ->and($events[0]->resource_id)->toBe($this->id)
        ->and($events->toJson(JSON_UNESCAPED_UNICODE))->not->toContain('内容に含まれる語')->not->toContain('題名に含まれる語');
});

it('commits nothing when the audit record cannot be written', function (string $operation) {
    $client = loggedIn($this, $this->member);
    $taskBefore = DB::table('workflow_tasks')->where('workflow_id', $this->id)->get();
    $titleBefore = DB::table('workflows')->where('id', $this->id)->value('title');
    $version = DB::table('workflows')->where('id', $this->id)->value('lock_version');
    useAuditWriter(new FailingAuditWriter('53100', 'could not extend file: No space left on device'));

    $response = match ($operation) {
        'edit' => putTask($client, $this->id),
        'title' => $client->send('PATCH', WORKFLOWS.'/'.$this->id, ['title' => 'x'], ifMatch(1)),
        'add' => $client->send('POST', WORKFLOWS.'/'.$this->id.'/tasks', taskBody(), ifMatch(1)),
    };

    $response->assertStatus(503)->assertJsonPath('code', 'SERVICE_UNAVAILABLE');

    expect(DB::table('workflow_revisions')->where('workflow_id', $this->id)->count())->toBe(1)
        ->and(DB::table('workflow_tasks')->where('workflow_id', $this->id)->get())->toEqual($taskBefore)
        ->and(DB::table('workflows')->where('id', $this->id)->value('title'))->toBe($titleBefore)
        ->and(DB::table('workflows')->where('id', $this->id)->value('lock_version'))->toBe($version);
})->with(['edit', 'title', 'add']);

it('refuses to start an edit while the audit log is known to be unavailable', function () {
    $client = loggedIn($this, $this->member);
    useAuditWriter(new FailingAuditWriter('53100', 'could not extend file: No space left on device'));
    app(AuditLogger::class)->recordAfterTransaction(AuditEntry::system(AuditEventType::AnalysisFailed, $this->member, 'failure'), 'test');

    putTask($client, $this->id)->assertStatus(503);

    expect(DB::table('workflow_revisions')->where('workflow_id', $this->id)->count())->toBe(1);
});
