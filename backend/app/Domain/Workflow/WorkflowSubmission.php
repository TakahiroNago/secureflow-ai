<?php

namespace App\Domain\Workflow;

use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowRevision;
use App\Models\WorkflowTask;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Support\Facades\DB;

/**
 * Draft to Pending (docs/api-design.md §3.4). An organization with nobody to approve can still submit: the screen
 * says so, and the workflow simply waits.
 */
final readonly class WorkflowSubmission
{
    public function __construct(
        private AuditAvailability $availability,
        private AuditLogger $audit,
        private WorkflowTransition $transition,
    ) {}

    /**
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function submit(User $user, Workflow $workflow): void
    {
        $this->availability->assertAvailable();

        SingleAttemptTransaction::run(DB::connection(), function () use ($user, $workflow): void {
            $locked = Workflow::query()->whereKey($workflow->id)->lockForUpdate()->firstOrFail();
            WorkflowStateMachine::next($locked->status, WorkflowEvent::Submit);

            $revision = WorkflowRevision::query()->whereKey($locked->current_revision_id)->first();
            $tasks = WorkflowTask::query()->where('workflow_id', $locked->id)->orderBy('position')->get();
            $refusal = ApprovalEligibility::submissionRefusal($revision, $tasks);

            if ($refusal !== null) {
                throw WorkflowDecisions::conflictFor($refusal);
            }

            $this->transition->apply($locked, WorkflowEvent::Submit);
            $locked->forceFill(['submitted_at' => now()])->save();

            $this->audit->recordInTransaction(
                AuditEntry::byUserOn(AuditEventType::WorkflowSubmitted, $user, 'workflow', $locked->id, ['revision_no' => (int) $revision?->revision_no]),
                'workflow_submitted_unrecorded',
            );
        });
    }
}
