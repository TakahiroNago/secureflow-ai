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
use Closure;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * docs/api-design.md §3.4. Each change runs under the workflow's row lock, and commits together with its
 * new revision and audit record. The fields a client can set are listed once, in TaskRequest: permissions
 * and the policy decision always come from ActionCatalog.
 */
final readonly class WorkflowEditor
{
    private const MAX_TASKS = 10;

    private const CHANGE_TASK = 'task';

    private const CHANGE_TITLE = 'title';

    public function __construct(
        private AuditAvailability $availability,
        private AuditLogger $audit,
        private WorkflowTransition $transition,
        private WorkflowRevisions $revisions,
    ) {}

    /**
     * The title is not part of the plan, so there is no new revision and the state stays. It is still
     * refused while the workflow cannot be edited.
     *
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function updateTitle(User $user, Workflow $workflow, int $expectedRevisionNo, string $title): void
    {
        $this->availability->assertAvailable();

        SingleAttemptTransaction::run(DB::connection(), function () use ($user, $workflow, $expectedRevisionNo, $title): void {
            $locked = $this->lockAtRevision($workflow, $expectedRevisionNo);
            WorkflowStateMachine::next($locked->status, WorkflowEvent::Edit);

            $locked->forceFill(['title' => $title, 'lock_version' => $locked->lock_version + 1])->save();

            $this->recordUpdate($user, $locked, $expectedRevisionNo, self::CHANGE_TITLE);
        });
    }

    /**
     * @param  array<string, mixed>  $fields
     *
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function updateTask(User $user, Workflow $workflow, WorkflowTask $task, int $expectedRevisionNo, array $fields): void
    {
        $this->change($user, $workflow, $expectedRevisionNo, function () use ($task, $fields): void {
            $task->forceFill([...$fields, ...WorkflowRevisions::derived((string) $fields['action_type'])])->save();
        });
    }

    /**
     * @param  array<string, mixed>  $fields
     *
     * @throws ValidationException when the workflow already has the most tasks it can have
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function addTask(User $user, Workflow $workflow, int $expectedRevisionNo, array $fields): void
    {
        $this->change($user, $workflow, $expectedRevisionNo, function (Workflow $locked) use ($fields): void {
            $count = WorkflowTask::query()->where('workflow_id', $locked->id)->count();

            if ($count >= self::MAX_TASKS) {
                throw ValidationException::withMessages(['tasks' => ['タスクは10件までです。']]);
            }

            (new WorkflowTask)->forceFill([
                ...$fields,
                ...WorkflowRevisions::derived((string) $fields['action_type']),
                'workflow_id' => $locked->id,
                'position' => (int) WorkflowTask::query()->where('workflow_id', $locked->id)->max('position') + 1,
                'ai_claimed_permissions' => [],
            ])->save();
        });
    }

    /**
     * @throws ValidationException when it is the last task
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function deleteTask(User $user, Workflow $workflow, WorkflowTask $task, int $expectedRevisionNo): void
    {
        $this->change($user, $workflow, $expectedRevisionNo, function (Workflow $locked) use ($task): void {
            if (WorkflowTask::query()->where('workflow_id', $locked->id)->count() <= 1) {
                throw ValidationException::withMessages(['tasks' => ['タスクは1件以上必要です。']]);
            }

            $position = $task->position;
            $task->delete();

            WorkflowTask::query()
                ->where('workflow_id', $locked->id)
                ->where('position', '>', $position)
                ->decrement('position');
        });
    }

    /**
     * @param  Closure(Workflow): void  $apply
     */
    private function change(User $user, Workflow $workflow, int $expectedRevisionNo, Closure $apply): void
    {
        $this->availability->assertAvailable();

        SingleAttemptTransaction::run(DB::connection(), function () use ($user, $workflow, $expectedRevisionNo, $apply): void {
            $locked = $this->lockAtRevision($workflow, $expectedRevisionNo);

            $this->transition->apply($locked, WorkflowEvent::Edit);
            $apply($locked);

            $revisionNo = $expectedRevisionNo + 1;
            $revision = $this->revisions->record($locked, $revisionNo, WorkflowRevisions::CHANGE_USER_EDIT, $user);
            $locked->forceFill(['current_revision_id' => $revision->id])->save();

            $this->recordUpdate($user, $locked, $revisionNo, self::CHANGE_TASK);
        });
    }

    /**
     * @throws WorkflowConflictException when the workflow has moved on since the client read it
     */
    private function lockAtRevision(Workflow $workflow, int $expectedRevisionNo): Workflow
    {
        $locked = Workflow::query()->whereKey($workflow->id)->lockForUpdate()->firstOrFail();
        $current = WorkflowRevision::query()->whereKey($locked->current_revision_id)->value('revision_no');

        if ($current !== $expectedRevisionNo) {
            throw WorkflowConflictException::revisionConflict();
        }

        return $locked;
    }

    private function recordUpdate(User $user, Workflow $workflow, int $revisionNo, string $change): void
    {
        $this->audit->recordInTransaction(
            AuditEntry::byUserOn(AuditEventType::WorkflowUpdated, $user, 'workflow', $workflow->id, ['revision_no' => $revisionNo, 'change' => $change]),
            'workflow_updated_unrecorded',
        );
    }
}
