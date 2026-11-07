<?php

namespace App\Http\Resources;

use App\Domain\Workflow\ApprovalEligibility;
use App\Domain\Workflow\WorkflowConflictException;
use App\Domain\Workflow\WorkflowEvent;
use App\Domain\Workflow\WorkflowStateMachine;
use App\Domain\Workflow\WorkflowStatus;
use App\Models\Approval;
use App\Models\Workflow;
use App\Models\WorkflowTask;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Facades\Gate;

/**
 * @mixin Workflow
 */
final class WorkflowResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $revision = $this->currentRevision;

        return [
            'id' => $this->id,
            'title' => $this->title,
            'status' => $this->status->value,
            'created_by' => ['id' => $this->creator->id, 'name' => $this->creator->name],
            'current_revision' => $revision === null ? null : [
                'no' => $revision->revision_no,
                'plan_hash' => $revision->plan_hash,
                'policy_version' => $revision->policy_version,
            ],
            'scan' => ScanStatus::of($revision?->scan),
            'max_severity' => $this->max_severity,
            'can_edit' => $this->can($request, 'update', WorkflowEvent::Edit),
            'can_submit' => $this->can($request, 'submit', WorkflowEvent::Submit),
            'can_reopen' => $this->can($request, 'reopen', WorkflowEvent::Reopen),
            'can_execute' => $this->status === WorkflowStatus::Approved && Gate::forUser($request->user())->allows('execute', $this->resource),
            'can_view_approval' => $this->status === WorkflowStatus::Pending && Gate::forUser($request->user())->allows('viewApprovalContext', $this->resource),
            'approver_available' => ApprovalEligibility::approverAvailable($this->resource),
            'decision' => $this->decisionOnCurrentRevision(),
            'tasks' => $this->tasks->map(fn (WorkflowTask $task) => [
                'id' => $task->id,
                'position' => $task->position,
                'title' => $task->title,
                'description' => $task->description,
                'action_type' => $task->action_type,
                'steps' => $task->steps,
                'priority' => $task->priority,
                'target_data' => $task->target_data,
                'impact_summary' => $task->impact_summary,
                'derived_permissions' => $task->derived_permissions,
                'policy_decision' => $task->policy_decision,
            ])->values(),
            'created_at' => $this->created_at?->toIso8601ZuluString(),
            'updated_at' => $this->updated_at?->toIso8601ZuluString(),
        ];
    }

    /**
     * What was decided on what is there now, in particular the reason for a rejection.
     *
     * @return array<string, mixed>|null
     */
    private function decisionOnCurrentRevision(): ?array
    {
        $approval = Approval::query()->with('decider')->where('workflow_revision_id', $this->current_revision_id)->first();

        return $approval === null ? null : [
            'decision' => $approval->decision,
            'comment' => $approval->comment,
            'decided_by' => ['id' => $approval->decider->id, 'name' => $approval->decider->name],
            'decided_at' => $approval->created_at->toIso8601ZuluString(),
        ];
    }

    /**
     * For the screen only. The server checks again on every change.
     */
    private function can(Request $request, string $ability, WorkflowEvent $event): bool
    {
        if (! Gate::forUser($request->user())->allows($ability, $this->resource)) {
            return false;
        }

        try {
            WorkflowStateMachine::next($this->status, $event);

            return true;
        } catch (WorkflowConflictException) {
            return false;
        }
    }
}
