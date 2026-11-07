<?php

namespace App\Domain\Execution;

use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Domain\Workflow\PlanHasher;
use App\Domain\Workflow\WorkflowConflictException;
use App\Domain\Workflow\WorkflowEvent;
use App\Domain\Workflow\WorkflowTransition;
use App\Models\Approval;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowExecution;
use App\Models\WorkflowRevision;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use PDOException;

/**
 * The worker's part. What runs is the plan as it was approved (plan_snapshot), not the task rows, which can be updated.
 * Nothing is tried again: the approval has been used, so a failure means reopening and approving again.
 */
final readonly class ExecutionProcessor
{
    public const ERROR_FAILED = 'EXECUTION_FAILED';

    public const ERROR_STALE = 'EXECUTION_STALE';

    public const ERROR_PLAN_CHANGED = 'EXECUTION_PLAN_CHANGED';

    public const ERROR_NO_HANDLER = 'EXECUTION_NO_HANDLER';

    public const ERROR_USER_INACTIVE = 'USER_INACTIVE';

    public function __construct(
        private AuditLogger $audit,
        private WorkflowTransition $transition,
    ) {}

    public function process(string $executionId): void
    {
        // Only one run can move the row out of queued. A job that comes back finds nothing to do.
        $claimed = WorkflowExecution::query()
            ->whereKey($executionId)
            ->where('status', WorkflowExecution::STATUS_QUEUED)
            ->update(['status' => WorkflowExecution::STATUS_RUNNING, 'started_at' => now(), 'heartbeat_at' => now()]);

        if ($claimed !== 1) {
            return;
        }

        try {
            $execution = WorkflowExecution::query()->findOrFail($executionId);
            $requester = User::query()->find($execution->requested_by);

            if ($requester === null || ! $requester->is_active) {
                $this->fail($executionId, self::ERROR_USER_INACTIVE);

                return;
            }

            $revision = WorkflowRevision::query()->findOrFail($execution->workflow_revision_id);

            if (! $this->isTheApprovedPlan($execution, $revision)) {
                $this->fail($executionId, self::ERROR_PLAN_CHANGED);

                return;
            }

            $results = $this->simulate($executionId, $revision);

            if ($results !== null) {
                $this->complete($execution, $results);
            }
        } catch (ServiceUnavailableException|QueryException|PDOException|WorkflowConflictException) {
            $this->fail($executionId, self::ERROR_FAILED);
        }
    }

    /**
     * Only a row that is still unfinished changes, so a late failure cannot undo a result. Never throws: it runs while
     * something else has already gone wrong, and the recovery command tries again. The record follows the commit, so
     * that an audit failure cannot leave the workflow running for ever.
     */
    public function fail(string $executionId, string $errorCode): void
    {
        try {
            $execution = SingleAttemptTransaction::run(DB::connection(), function () use ($executionId, $errorCode): ?WorkflowExecution {
                $found = WorkflowExecution::query()->findOrFail($executionId);
                $workflow = Workflow::query()->whereKey($found->workflow_id)->lockForUpdate()->firstOrFail();

                $changed = WorkflowExecution::query()
                    ->whereKey($executionId)
                    ->whereIn('status', [WorkflowExecution::STATUS_QUEUED, WorkflowExecution::STATUS_RUNNING])
                    ->update(['status' => WorkflowExecution::STATUS_FAILED, 'error_code' => $errorCode, 'finished_at' => now()]);

                if ($changed !== 1) {
                    return null;
                }

                $this->transition->apply($workflow, WorkflowEvent::Fail);

                return $found;
            });

            if ($execution !== null) {
                $this->audit->recordAfterTransaction(
                    AuditEntry::systemOn(AuditEventType::ExecutionFailed, $execution->organization_id, 'workflow', $execution->workflow_id, ['execution_id' => $execution->id, 'reason_code' => $errorCode], 'failure'),
                    'execution_failed_unrecorded',
                );
            }
        } catch (QueryException|PDOException|WorkflowConflictException $exception) {
            Log::error('execution.fail_not_recorded', [
                'metric' => 'execution.fail_not_recorded',
                'execution_id' => $executionId,
                'error_code' => $errorCode,
                'exception' => $exception::class,
            ]);
        }
    }

    private function isTheApprovedPlan(WorkflowExecution $execution, WorkflowRevision $revision): bool
    {
        $workflow = Workflow::query()->findOrFail($execution->workflow_id);
        $approval = Approval::query()->findOrFail($execution->approval_id);

        return $workflow->current_revision_id === $revision->id
            && hash_equals($revision->plan_hash, $approval->plan_hash)
            && PlanHasher::matches($revision->plan_snapshot, $revision->plan_hash);
    }

    /**
     * The heartbeat changes no row once the recovery command has given up on this run, and neither can complete().
     *
     * @return list<array{position: int, action_type: string, summary: string}>|null Null when it stopped, and has said why.
     */
    private function simulate(string $executionId, WorkflowRevision $revision): ?array
    {
        $results = [];
        /** @var list<array{position: int, action_type: string}> $tasks */
        $tasks = $revision->plan_snapshot['tasks'];

        foreach ($tasks as $task) {
            $summary = ExecutionSimulator::run($task['action_type']);

            if ($summary === null) {
                $this->fail($executionId, self::ERROR_NO_HANDLER);

                return null;
            }

            WorkflowExecution::query()
                ->whereKey($executionId)
                ->where('status', WorkflowExecution::STATUS_RUNNING)
                ->update(['heartbeat_at' => now()]);

            $results[] = ['position' => $task['position'], 'action_type' => $task['action_type'], 'summary' => $summary];
        }

        return $results;
    }

    /**
     * @param  list<array{position: int, action_type: string, summary: string}>  $results
     */
    private function complete(WorkflowExecution $execution, array $results): void
    {
        SingleAttemptTransaction::run(DB::connection(), function () use ($execution, $results): void {
            $workflow = Workflow::query()->whereKey($execution->workflow_id)->lockForUpdate()->firstOrFail();

            $changed = WorkflowExecution::query()
                ->whereKey($execution->id)
                ->where('status', WorkflowExecution::STATUS_RUNNING)
                ->update([
                    'status' => WorkflowExecution::STATUS_COMPLETED,
                    'result' => json_encode(['simulated' => true, 'tasks' => $results], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE),
                    'finished_at' => now(),
                ]);

            if ($changed !== 1) {
                return;
            }

            $this->transition->apply($workflow, WorkflowEvent::Complete);

            $this->audit->recordInTransaction(
                AuditEntry::systemOn(AuditEventType::ExecutionCompleted, $execution->organization_id, 'workflow', $workflow->id, ['execution_id' => $execution->id]),
                'execution_completed_unrecorded',
            );
        });
    }
}
