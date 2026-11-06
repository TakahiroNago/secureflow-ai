<?php

use App\Domain\Workflow\WorkflowEvent;
use App\Domain\Workflow\WorkflowStateMachine;
use App\Models\Organization;
use App\Models\Workflow;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;

/*
| The real answers over HTTP before the API exists (step 1-6). These routes exist only in this test,
| with the same middleware as routes/api.php, so that the production application has no such route.
*/

uses(DatabaseTransactions::class);

const VIEW_URI = '/api/v1/test-workflows/%s';

beforeEach(function () {
    $middleware = ['api', 'db.available', 'auth:sanctum', 'session.current', 'org.context'];

    Route::middleware([...$middleware, 'can:view,workflow'])->get('/api/v1/test-workflows/{workflow}', fn (Workflow $workflow) => ['id' => $workflow->id, 'title' => $workflow->title]);
    Route::middleware([...$middleware, 'can:update,workflow'])->get('/api/v1/test-workflows/{workflow}/update', fn (Workflow $workflow) => ['id' => $workflow->id]);
    Route::middleware([...$middleware, 'can:approve,workflow'])->get('/api/v1/test-workflows/{workflow}/approve', fn (Workflow $workflow) => ['id' => $workflow->id]);
    Route::middleware([...$middleware, 'can:view,workflow'])->get('/api/v1/test-workflows/{workflow}/conflict', function (Workflow $workflow) {
        WorkflowStateMachine::next($workflow->status, WorkflowEvent::Approve);
    });

    $this->org = Organization::factory()->create();
    $this->member = userIn($this->org->id);
    $this->workflow = workflowOf($this->member, ['title' => 'Confidential plan title']);
});

function assertProblem(TestResponse $response, int $status, string $code): void
{
    $response->assertStatus($status)
        ->assertHeader('Content-Type', 'application/problem+json')
        ->assertJsonPath('status', $status)
        ->assertJsonPath('code', $code);

    expect($response->getContent())->not->toContain('Confidential plan title')
        ->not->toContain('App\\')
        ->not->toContain('workflows');
}

it('answers the owner', function () {
    loggedIn($this, $this->member)->send('GET', sprintf(VIEW_URI, $this->workflow->id))
        ->assertOk()
        ->assertJsonPath('id', $this->workflow->id);
});

it('answers 401 without a session', function () {
    spa($this)->csrf()->send('GET', sprintf(VIEW_URI, $this->workflow->id))->assertStatus(401);
});

it('ST-23: answers 404 for a workflow of another organization, whatever the role', function (string $role) {
    $outsider = userIn(Organization::factory()->create()->id, $role);

    assertProblem(loggedIn($this, $outsider)->send('GET', sprintf(VIEW_URI, $this->workflow->id)), 404, 'NOT_FOUND');
})->with(['admin', 'member', 'auditor']);

it('ST-12: answers 404 for another member\'s workflow', function () {
    $other = userIn($this->org->id);

    assertProblem(loggedIn($this, $other)->send('GET', sprintf(VIEW_URI, $this->workflow->id)), 404, 'NOT_FOUND');
});

it('reveals nothing: another organization, another member and no such workflow look the same', function () {
    $outsider = userIn(Organization::factory()->create()->id);
    $other = userIn($this->org->id);
    $missing = '0193a000-0000-7000-8000-00000000dead';

    $bodies = [
        loggedIn($this, $outsider)->send('GET', sprintf(VIEW_URI, $this->workflow->id))->json(),
        loggedIn($this, $other)->send('GET', sprintf(VIEW_URI, $this->workflow->id))->json(),
        loggedIn($this, $other)->send('GET', sprintf(VIEW_URI, $missing))->json(),
    ];

    $withoutTrace = array_map(fn (array $body) => collect($body)->except('trace_id')->all(), $bodies);

    expect($withoutTrace[1])->toBe($withoutTrace[0])->and($withoutTrace[2])->toBe($withoutTrace[0]);
});

it('answers 404, not an error, for an id that is not a UUID', function () {
    assertProblem(loggedIn($this, $this->member)->send('GET', sprintf(VIEW_URI, 'not-a-uuid')), 404, 'NOT_FOUND');
});

it('answers 403 when the role is missing', function () {
    $auditor = userIn($this->org->id, 'auditor');

    assertProblem(loggedIn($this, $auditor)->send('GET', sprintf(VIEW_URI, $this->workflow->id).'/update'), 403, 'FORBIDDEN');
});

it('ST-06: answers 403 with the approver code for a member or auditor', function (string $role, bool $owner) {
    $user = $owner ? $this->member : userIn($this->org->id, $role);

    assertProblem(loggedIn($this, $user)->send('GET', sprintf(VIEW_URI, $this->workflow->id).'/approve'), 403, 'APPROVER_ROLE_REQUIRED');
})->with([
    'the creator as a member' => ['member', true],
    'an auditor' => ['auditor', false],
]);

it('ST-21: answers 403 with the self-approval code to an admin who created the workflow', function () {
    $admin = userIn($this->org->id, 'admin');
    $own = workflowOf($admin);

    assertProblem(loggedIn($this, $admin)->send('GET', sprintf(VIEW_URI, $own->id).'/approve'), 403, 'SELF_APPROVAL_FORBIDDEN');
});

it('allows another admin to approve', function () {
    loggedIn($this, userIn($this->org->id, 'admin'))
        ->send('GET', sprintf(VIEW_URI, $this->workflow->id).'/approve')
        ->assertOk();
});

it('answers 409 for a transition the state does not allow', function () {
    assertProblem(loggedIn($this, $this->member)->send('GET', sprintf(VIEW_URI, $this->workflow->id).'/conflict'), 409, 'WORKFLOW_INVALID_STATE');
});

it('still leaves other APIs unchanged: an unknown path under v1 is a 404 in the same format', function () {
    assertProblem(spa($this)->send('GET', '/api/v1/no-such-path'), 404, 'NOT_FOUND');
});
