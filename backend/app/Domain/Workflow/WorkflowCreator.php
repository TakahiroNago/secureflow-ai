<?php

namespace App\Domain\Workflow;

use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Domain\Security\ScanRecorder;
use App\Models\AiAnalysisRequest;
use App\Models\SecurityScan;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowTask;
use App\Security\Output\ValidatedTask;
use App\Security\Scanning\InputScanResult;
use App\Security\Scanning\Severity;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PDOException;

final readonly class WorkflowCreator
{
    public function __construct(
        private WorkflowRevisions $revisions,
        private AuditLogger $audit,
        private ScanRecorder $recorder,
    ) {}

    /**
     * Everything or nothing, the audit record included. The row is checked under its lock, because the
     * recovery command may have given up on it during the AI call.
     *
     * @param  list<ValidatedTask>  $tasks  At least one: the schema requires it. Their text is already masked.
     * @param  InputScanResult  $outputScan  The scan of that text, which did not stop the work.
     *
     * @throws ServiceUnavailableException when the audit record cannot be written
     * @throws InvalidPlanException
     * @throws QueryException|PDOException when the database fails: the transaction has rolled back
     */
    public function create(AiAnalysisRequest $analysis, User $user, array $tasks, InputScanResult $outputScan): void
    {
        SingleAttemptTransaction::run(DB::connection(), function () use ($analysis, $user, $tasks, $outputScan): void {
            $locked = AiAnalysisRequest::query()
                ->whereKey($analysis->id)
                ->where('status', AiAnalysisRequest::STATUS_PROCESSING)
                ->lockForUpdate()
                ->first();

            if ($locked === null) {
                return;
            }

            $workflow = new Workflow;
            $inputSeverity = SecurityScan::query()->whereKey($locked->input_scan_id)->value('max_severity');

            $workflow->forceFill([
                'created_by' => $user->id,
                'title' => $tasks[0]->title,
                'status' => WorkflowStatus::Draft,
                'source_input_masked' => $locked->input_masked,
                // A warning about the input still counts when what the AI wrote is clean.
                'max_severity' => Severity::higher(is_string($inputSeverity) ? Severity::from($inputSeverity) : null, $outputScan->maxSeverity)?->value,
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

            $revisionId = (string) Str::uuid7();
            $scan = $this->recorder->record($user, SecurityScan::TARGET_OUTPUT, $locked->id, $outputScan);
            $revision = $this->revisions->record($revisionId, $workflow, 1, WorkflowRevisions::CHANGE_AI_GENERATED, $user, $scan);
            $workflow->forceFill(['current_revision_id' => $revision->id])->save();

            $locked->forceFill([
                'status' => AiAnalysisRequest::STATUS_SUCCEEDED,
                'workflow_id' => $workflow->id,
                'output_scan_id' => $scan->id,
                'input_masked' => null,
                'finished_at' => now(),
            ])->save();

            $this->audit->recordInTransaction(
                AuditEntry::byUserOn(AuditEventType::WorkflowCreated, $user, 'workflow', $workflow->id, ['revision_no' => 1]),
                'workflow_created_unrecorded',
            );
        });
    }
}
