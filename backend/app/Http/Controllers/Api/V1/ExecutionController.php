<?php

namespace App\Http\Controllers\Api\V1;

use App\Domain\Execution\ExecutionService;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowExecution;
use App\Models\WorkflowRevision;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

/**
 * docs/api-design.md §3.6. What the policy decides is on the routes.
 */
final class ExecutionController extends Controller
{
    private const KEY_PATTERN = '/^[A-Za-z0-9._:-]{1,100}$/D';

    private const HISTORY_LIMIT = 50;

    public function store(Request $request, Workflow $workflow, ExecutionService $service): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        $key = (string) $request->header('Idempotency-Key');

        if (preg_match(self::KEY_PATTERN, $key) !== 1) {
            throw ValidationException::withMessages(['idempotency_key' => ['Idempotency-Key ヘッダに UUID を指定してください。']]);
        }

        $execution = $service->request($user, $workflow, $key);

        return response()->json(['data' => ['execution_id' => $execution->id, 'status' => $execution->status]], 202);
    }

    public function index(Workflow $workflow): JsonResponse
    {
        $executions = WorkflowExecution::query()
            ->where('workflow_id', $workflow->id)
            ->orderByDesc('created_at')
            ->orderByDesc('id')
            ->limit(self::HISTORY_LIMIT)
            ->get();
        $revisions = WorkflowRevision::query()->whereIn('id', $executions->pluck('workflow_revision_id'))->pluck('revision_no', 'id');

        return response()->json(['data' => $executions->map(fn (WorkflowExecution $execution) => [
            'id' => $execution->id,
            'status' => $execution->status,
            'revision_no' => $revisions[$execution->workflow_revision_id] ?? null,
            'requested_by' => $execution->requested_by,
            'error_code' => $execution->error_code,
            'result' => $execution->result,
            'created_at' => $execution->created_at?->toIso8601ZuluString(),
            'started_at' => $execution->started_at?->toIso8601ZuluString(),
            'finished_at' => $execution->finished_at?->toIso8601ZuluString(),
        ])->values()], 200, [], JSON_UNESCAPED_UNICODE);
    }
}
