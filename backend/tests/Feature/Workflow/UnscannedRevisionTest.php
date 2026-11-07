<?php

use App\Domain\Execution\ExecutionVerifier;
use App\Domain\Workflow\ApprovalEligibility;
use App\Domain\Workflow\WorkflowConflictException;
use App\Domain\Workflow\WorkflowDecisions;
use App\Domain\Workflow\WorkflowSubmission;
use App\Models\Approval;
use App\Models\Organization;
use App\Models\Workflow;
use App\Models\WorkflowRevision;
use App\Models\WorkflowTask;
use App\Support\Organization\OrganizationContext;
use Illuminate\Database\QueryException;

/*
| Rows from before step 2-3 have no scan, and a check now stops new ones. So the check is lifted to make such a row
| (test database only, committed, and put back straight away). NULL must never read as allowed (decision 1 of step 2-5).
*/

const NEW_ROWS_SCANNED = 'ALTER TABLE workflow_revisions ADD CONSTRAINT workflow_revisions_new_rows_scanned CHECK (scan_id IS NOT NULL) NOT VALID';

function unscannedWorkflowOf(Organization $org, string $creator, string $status): Workflow
{
    $db = ownerDb();
    $workflow = app(OrganizationContext::class)->run($org->id, fn () => Workflow::factory()->create(['created_by' => $creator, 'status' => $status]));

    $db->statement('ALTER TABLE workflow_revisions DROP CONSTRAINT workflow_revisions_new_rows_scanned');

    try {
        $revision = insertRevision($db, $workflow, ['scan_id' => null, 'scan_decision' => null]);
    } finally {
        $db->statement(NEW_ROWS_SCANNED);
    }

    insertTask($db, $workflow);
    $db->table('workflows')->where('id', $workflow->id)->update(['current_revision_id' => $revision]);

    return $workflow->refresh();
}

function inOrganization(Organization $org, Closure $callback): mixed
{
    return app(OrganizationContext::class)->run($org->id, $callback);
}

beforeEach(function () {
    $this->org = Organization::factory()->create();
    $this->owner = userIn($this->org->id);
    $this->admin = userIn($this->org->id, 'admin');
});

afterEach(function () {
    resetWorkflowTables();
    ownerDb()->table('users')->whereIn('id', [$this->owner->id, $this->admin->id])->delete();
    ownerDb()->table('organizations')->where('id', $this->org->id)->delete();
});

it('refuses to submit a revision that was never scanned', function () {
    $workflow = unscannedWorkflowOf($this->org, $this->owner->id, 'draft');

    try {
        inOrganization($this->org, fn () => app(WorkflowSubmission::class)->submit($this->owner, Workflow::query()->findOrFail($workflow->id)));
        $this->fail('It was submitted.');
    } catch (WorkflowConflictException $exception) {
        expect($exception->problemCode)->toBe('SCAN_REQUIRED');
    }

    expect(ownerDb()->table('workflows')->where('id', $workflow->id)->value('status'))->toBe('draft');
});

it('refuses to approve a revision that was never scanned, and says so beforehand', function () {
    $workflow = unscannedWorkflowOf($this->org, $this->owner->id, 'pending');
    $revision = ownerDb()->table('workflow_revisions')->where('workflow_id', $workflow->id)->sole();

    inOrganization($this->org, function () use ($workflow, $revision): void {
        $fresh = Workflow::query()->findOrFail($workflow->id);
        $tasks = WorkflowTask::query()->where('workflow_id', $fresh->id)->get();
        $model = WorkflowRevision::query()->findOrFail($revision->id);

        expect(ApprovalEligibility::cannotApproveReason($this->admin, $fresh, $model, $tasks))->toBe('SCAN_REQUIRED');

        try {
            app(WorkflowDecisions::class)->approve($this->admin, $fresh, $revision->revision_no, $revision->plan_hash, true, null);
            $this->fail('It was approved.');
        } catch (WorkflowConflictException $exception) {
            expect($exception->problemCode)->toBe('SCAN_REQUIRED');
        }
    });

    expect(ownerDb()->table('approvals')->where('workflow_id', $workflow->id)->count())->toBe(0)
        ->and(ownerDb()->table('workflows')->where('id', $workflow->id)->value('status'))->toBe('pending');
});

it('refuses to execute a revision that was never scanned, even when it is approved', function () {
    $workflow = unscannedWorkflowOf($this->org, $this->owner->id, 'approved');
    $revision = ownerDb()->table('workflow_revisions')->where('workflow_id', $workflow->id)->sole();
    insertApproval(ownerDb(), $workflow, $revision->id, $this->admin->id, ['plan_hash' => $revision->plan_hash]);

    $refusal = inOrganization($this->org, fn () => ExecutionVerifier::refusal(
        Workflow::query()->findOrFail($workflow->id),
        WorkflowRevision::query()->findOrFail($revision->id),
        Approval::query()->where('workflow_id', $workflow->id)->sole(),
        WorkflowTask::query()->where('workflow_id', $workflow->id)->get(),
    ));

    expect($refusal)->toBe('SCAN_REQUIRED');
});

it('leaves the check that stops new unscanned rows in place', function () {
    $workflow = unscannedWorkflowOf($this->org, $this->owner->id, 'draft');

    expect(fn () => insertRevision(ownerDb(), $workflow, ['revision_no' => 2, 'scan_id' => null, 'scan_decision' => null]))
        ->toThrow(QueryException::class, 'workflow_revisions_new_rows_scanned');
});
