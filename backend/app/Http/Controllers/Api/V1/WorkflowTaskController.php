<?php

namespace App\Http\Controllers\Api\V1;

use App\Domain\Workflow\WorkflowEditor;
use App\Http\Controllers\Controller;
use App\Http\Requests\TaskRequest;
use App\Http\Resources\WorkflowResource;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowTask;
use App\Support\Http\IfMatch;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Each change makes a new revision and answers with the whole workflow, so that the client has the
 * revision number it needs for the next change.
 */
final class WorkflowTaskController extends Controller
{
    public function __construct(private readonly WorkflowEditor $editor) {}

    public function store(TaskRequest $request, Workflow $workflow): JsonResponse
    {
        $this->editor->addTask($this->user($request), $workflow, IfMatch::revisionNo($request), $request->validated());

        return WorkflowController::resource($workflow)->response()->setStatusCode(201);
    }

    public function update(TaskRequest $request, Workflow $workflow, WorkflowTask $task): WorkflowResource
    {
        $this->editor->updateTask($this->user($request), $workflow, $task, IfMatch::revisionNo($request), $request->validated());

        return WorkflowController::resource($workflow);
    }

    public function destroy(Request $request, Workflow $workflow, WorkflowTask $task): WorkflowResource
    {
        $this->editor->deleteTask($this->user($request), $workflow, $task, IfMatch::revisionNo($request));

        return WorkflowController::resource($workflow);
    }

    private function user(Request $request): User
    {
        /** @var User $user */
        $user = $request->user();

        return $user;
    }
}
