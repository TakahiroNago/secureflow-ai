<?php

namespace App\Domain\Workflow;

use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Models\AiAnalysisRequest;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowTask;
use App\Security\Output\ValidatedTask;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PDOException;

final readonly class WorkflowCreator
{
    public function __construct(
        private WorkflowRevisions $revisions,
        private AuditLogger $audit,
    ) {}

    /**
     * Everything or nothing, the audit record included. The row is checked under its lock, because the
     * recovery command may have given up on it during the AI call.
     *
     * @param  list<ValidatedTask>  $tasks  At least one: the schema requires it.
     *
     * @throws ServiceUnavailableException when the audit record cannot be written
     * @throws InvalidPlanException
     * @throws QueryException|PDOException when the database fails: the transaction has rolled back
     */
    public function create(AiAnalysisRequest $analysis, User $user, array $tasks): void
    {
        SingleAttemptTransaction::run(DB::connection(), function () use ($analysis, $user, $tasks): void {
            $locked = AiAnalysisRequest::query()
                ->whereKey($analysis->id)
                ->where('status', AiAnalysisRequest::STATUS_PROCESSING)
                ->lockForUpdate()
                ->first();

            if ($locked === null) {
                return;
            }

            $workflow = new Workflow;
            $workflow->forceFill([
                'created_by' => $user->id,
                'title' => $tasks[0]->title,
                'status' => WorkflowStatus::Draft,
            ])->save();

            foreach ($tasks as $index => $task) {
                (new WorkflowTask)->forceFill([
                    'workflow_id' => $workflow->id,
                    'position' => $index + 1,
                    'title' => $task->title,
                    'description' => $task->description,
                    'action_type' => $task->actionType,
                    'steps' => $task->steps,
                    'priority' => $task->priority,
                    'target_data' => $task->targetData,
                    'impact_summary' => $task->impactSummary,
                    'ai_claimed_permissions' => $task->requestedPermissions,
                    ...WorkflowRevisions::derived($task->actionType),
                ])->save();
            }

            $revision = $this->revisions->record($workflow, 1, WorkflowRevisions::CHANGE_AI_GENERATED, $user);
            $workflow->forceFill(['current_revision_id' => $revision->id])->save();

            $locked->forceFill([
                'status' => AiAnalysisRequest::STATUS_SUCCEEDED,
                'workflow_id' => $workflow->id,
                'finished_at' => now(),
            ])->save();

            $this->audit->recordInTransaction(
                AuditEntry::byUserOn(AuditEventType::WorkflowCreated, $user, 'workflow', $workflow->id, ['revision_no' => 1]),
                'workflow_created_unrecorded',
            );
        });
    }
}
