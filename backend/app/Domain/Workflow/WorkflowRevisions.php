<?php

namespace App\Domain\Workflow;

use App\Models\SecurityScan;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowRevision;
use App\Models\WorkflowTask;
use App\Security\Policy\ActionCatalog;
use App\Security\Policy\PolicyDecision;
use Illuminate\Database\Eloquent\Collection;

/**
 * A revision is the immutable record of the tasks as they are now (docs/database-design.md §2), and of the
 * scan of exactly that text.
 */
final class WorkflowRevisions
{
    public const CHANGE_AI_GENERATED = 'ai_generated';

    public const CHANGE_USER_EDIT = 'user_edit';

    public const CHANGE_REOPEN = 'reopen';

    /**
     * Inside the caller's transaction, with the workflow row locked.
     *
     * @param  string  $id  Chosen by the caller, because the scan names the revision it is for.
     *
     * @throws InvalidPlanException
     */
    public function record(string $id, Workflow $workflow, int $revisionNo, string $changeType, User $user, SecurityScan $scan): WorkflowRevision
    {
        $tasks = WorkflowTask::query()->where('workflow_id', $workflow->id)->orderBy('position')->get();

        $snapshot = self::snapshotOf($workflow, $revisionNo, ActionCatalog::VERSION, $tasks);

        $revision = new WorkflowRevision;
        $revision->forceFill([
            'id' => $id,
            'workflow_id' => $workflow->id,
            'revision_no' => $revisionNo,
            'plan_snapshot' => $snapshot,
            'plan_hash' => PlanHasher::hash($snapshot),
            'hash_version' => PlanHasher::HASH_VERSION,
            'policy_version' => ActionCatalog::VERSION,
            'scan_id' => $scan->id,
            'scan_decision' => $scan->decision,
            'change_type' => $changeType,
            'created_by' => $user->id,
        ])->save();

        return $revision;
    }

    /**
     * The normalized plan of these tasks, in the form stored and hashed.
     *
     * @param  Collection<int, WorkflowTask>  $tasks
     * @return array<string, mixed>
     *
     * @throws InvalidPlanException
     */
    public static function snapshotOf(Workflow $workflow, int $revisionNo, string $policyVersion, Collection $tasks): array
    {
        return PlanHasher::normalize([
            'hash_version' => PlanHasher::HASH_VERSION,
            'organization_id' => $workflow->organization_id,
            'workflow_id' => $workflow->id,
            'revision_no' => $revisionNo,
            'policy_version' => $policyVersion,
            'tasks' => $tasks->map(fn (WorkflowTask $task) => [
                'position' => $task->position,
                'title' => $task->title,
                'description' => $task->description,
                'action_type' => $task->action_type,
                'steps' => $task->steps,
                'priority' => $task->priority,
                'target_data' => $task->target_data,
                'impact_summary' => $task->impact_summary,
                'permissions' => $task->derived_permissions,
                'policy_decision' => $task->policy_decision,
            ])->values()->all(),
        ]);
    }

    /**
     * The server's view of a task's permissions. Whatever a client or the AI says is not an input here.
     *
     * @return array{derived_permissions: list<string>, policy_decision: string}
     */
    public static function derived(string $actionType): array
    {
        $permissions = ActionCatalog::permissions($actionType);
        sort($permissions, SORT_STRING);

        return [
            'derived_permissions' => $permissions,
            'policy_decision' => (ActionCatalog::decision($actionType) ?? PolicyDecision::Forbidden)->value,
        ];
    }
}
