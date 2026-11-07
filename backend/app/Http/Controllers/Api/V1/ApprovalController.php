<?php

namespace App\Http\Controllers\Api\V1;

use App\Domain\Workflow\ApprovalEligibility;
use App\Domain\Workflow\WorkflowDecisions;
use App\Domain\Workflow\WorkflowStatus;
use App\Http\Controllers\Controller;
use App\Http\Requests\ApproveWorkflowRequest;
use App\Http\Requests\ListApprovalsRequest;
use App\Http\Requests\RejectWorkflowRequest;
use App\Http\Resources\ApprovalSummaryResource;
use App\Http\Resources\ScanStatus;
use App\Http\Resources\WorkflowResource;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowTask;
use App\Security\Policy\ActionCatalog;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

/**
 * docs/api-design.md §3.5. What the policy decides is on the routes.
 */
final class ApprovalController extends Controller
{
    private const PAGE_SIZE = 20;

    public function index(ListApprovalsRequest $request): AnonymousResourceCollection
    {
        $workflows = Workflow::query()
            ->with(['currentRevision', 'creator', 'tasks' => fn ($query) => $query->orderBy('position')])
            ->where('status', WorkflowStatus::Pending->value)
            ->orderByDesc('created_at')
            ->orderByDesc('id')
            ->cursorPaginate($request->integer('limit', self::PAGE_SIZE));

        return ApprovalSummaryResource::collection($workflows);
    }

    /**
     * Everything the hash covers is shown, so that nobody approves what they could not see.
     */
    public function context(Request $request, Workflow $workflow): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        $workflow->load(['currentRevision.scan.findings', 'creator', 'tasks' => fn ($query) => $query->orderBy('position')]);
        $revision = $workflow->currentRevision;
        $reason = ApprovalEligibility::cannotApproveReason($user, $workflow, $revision, $workflow->tasks);

        return response()->json(['data' => [
            'workflow_id' => $workflow->id,
            'title' => $workflow->title,
            'status' => $workflow->status->value,
            'revision_no' => $revision?->revision_no,
            'plan_hash' => $revision?->plan_hash,
            'policy_version' => $revision?->policy_version,
            'tasks' => $workflow->tasks->map(fn (WorkflowTask $task) => [
                'position' => $task->position,
                'title' => $task->title,
                'description' => $task->description,
                'action_type' => $task->action_type,
                'ai_feature' => ActionCatalog::aiFeature($task->action_type),
                'steps' => $task->steps,
                'priority' => $task->priority,
                'target_data' => $task->target_data,
                'derived_permissions' => $task->derived_permissions,
                'impact_summary' => $task->impact_summary,
                'policy_decision' => $task->policy_decision,
            ])->values(),
            // The most found at any time, which is what the confirmation is about, with the scan of this revision.
            'security' => [...ScanStatus::of($revision?->scan), 'max_severity' => $workflow->max_severity],
            'requires_risk_acknowledgement' => ApprovalEligibility::requiresRiskAcknowledgement($workflow),
            'created_by' => ['id' => $workflow->creator->id, 'name' => $workflow->creator->name],
            'can_approve' => $reason === null,
            'cannot_approve_reason' => $reason,
            'approver_available' => ApprovalEligibility::approverAvailable($workflow),
        ]], 200, [], JSON_UNESCAPED_UNICODE);
    }

    public function approve(ApproveWorkflowRequest $request, Workflow $workflow, WorkflowDecisions $decisions): WorkflowResource
    {
        /** @var User $user */
        $user = $request->user();
        $comment = $request->input('comment');

        $decisions->approve(
            $user,
            $workflow,
            $request->integer('revision_no'),
            $request->string('plan_hash')->toString(),
            $request->boolean('acknowledged_risks'),
            is_string($comment) ? $comment : null,
        );

        return WorkflowController::resource($workflow);
    }

    public function reject(RejectWorkflowRequest $request, Workflow $workflow, WorkflowDecisions $decisions): WorkflowResource
    {
        /** @var User $user */
        $user = $request->user();

        $decisions->reject(
            $user,
            $workflow,
            $request->integer('revision_no'),
            $request->string('plan_hash')->toString(),
            $request->string('reason')->toString(),
        );

        return WorkflowController::resource($workflow);
    }
}
