<?php

namespace App\Http\Controllers\Api\V1;

use App\Domain\Workflow\WorkflowEditor;
use App\Domain\Workflow\WorkflowSubmission;
use App\Http\Controllers\Controller;
use App\Http\Requests\ListWorkflowsRequest;
use App\Http\Requests\UpdateWorkflowRequest;
use App\Http\Resources\WorkflowResource;
use App\Http\Resources\WorkflowSummaryResource;
use App\Models\Approval;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowExecution;
use App\Models\WorkflowRevision;
use App\Support\Http\IfMatch;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

final class WorkflowController extends Controller
{
    private const PAGE_SIZE = 20;

    private const MEMBER_ROLE = 'member';

    /**
     * A member sees their own workflows, an admin or auditor all in the organization (docs/api-design.md §3.4).
     */
    public function index(ListWorkflowsRequest $request): AnonymousResourceCollection
    {
        /** @var User $user */
        $user = $request->user();

        $workflows = Workflow::query()
            ->with(['currentRevision', 'creator'])
            ->when($user->role === self::MEMBER_ROLE, fn ($query) => $query->where('created_by', $user->id))
            ->when($request->filled('status'), fn ($query) => $query->where('status', $request->string('status')->toString()))
            ->orderByDesc('created_at')
            ->orderByDesc('id')
            ->cursorPaginate($request->integer('limit', self::PAGE_SIZE));

        return WorkflowSummaryResource::collection($workflows);
    }

    public function show(Workflow $workflow): WorkflowResource
    {
        return self::resource($workflow);
    }

    public function update(UpdateWorkflowRequest $request, Workflow $workflow, WorkflowEditor $editor): WorkflowResource
    {
        /** @var User $user */
        $user = $request->user();

        $editor->updateTitle($user, $workflow, IfMatch::revisionNo($request), $request->string('title')->toString());

        return self::resource($workflow);
    }

    public function submit(Request $request, Workflow $workflow, WorkflowSubmission $submission): WorkflowResource
    {
        /** @var User $user */
        $user = $request->user();

        $submission->submit($user, $workflow);

        return self::resource($workflow);
    }

    public function reopen(Request $request, Workflow $workflow, WorkflowEditor $editor): WorkflowResource
    {
        /** @var User $user */
        $user = $request->user();

        $editor->reopen($user, $workflow);

        return self::resource($workflow);
    }

    /**
     * What happened, without the content of the plans: a revision's snapshot stays on the server.
     */
    public function history(Workflow $workflow): JsonResponse
    {
        $id = $workflow->id;

        return response()->json(['data' => [
            'revisions' => WorkflowRevision::query()->where('workflow_id', $id)->orderByDesc('revision_no')
                ->get(['id', 'revision_no', 'plan_hash', 'policy_version', 'scan_decision', 'change_type', 'created_by', 'created_at']),
            'approvals' => Approval::query()->where('workflow_id', $id)->orderByDesc('created_at')
                ->get(['id', 'workflow_revision_id', 'decision', 'decided_by', 'comment', 'created_at']),
            'executions' => WorkflowExecution::query()->where('workflow_id', $id)->orderByDesc('created_at')
                ->get(['id', 'workflow_revision_id', 'status', 'requested_by', 'error_code', 'created_at', 'finished_at']),
        ]]);
    }

    public static function resource(Workflow $workflow): WorkflowResource
    {
        $fresh = Workflow::query()
            ->with(['currentRevision.scan.findings', 'creator', 'tasks' => fn ($query) => $query->orderBy('position')])
            ->findOrFail($workflow->id);

        return new WorkflowResource($fresh);
    }
}
