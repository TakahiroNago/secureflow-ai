<?php

namespace App\Domain\Workflow;

use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Domain\Security\InputBlockedException;
use App\Domain\Security\ScanRecorder;
use App\Models\SecurityScan;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowRevision;
use App\Models\WorkflowTask;
use App\Security\Scanning\InputScanner;
use App\Security\Scanning\InputScanResult;
use App\Security\Scanning\Severity;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Closure;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

/**
 * docs/api-design.md §3.4. Each change runs under the workflow's row lock, and commits together with its
 * new revision, its scan and its audit record. The fields a client can set are listed once, in TaskRequest:
 * permissions and the policy decision always come from ActionCatalog.
 *
 * The plan as it would become is scanned before the lock is taken, because a scan can take seconds. Under the
 * lock the revision number is compared again: every change of a task changes it, so an equal number means the
 * scan looked at exactly what is there. The whole plan is scanned, not only the change, because a revision's
 * scan vouches for all of it, and a task from before step 2-3 was never scanned.
 *
 * @phpstan-type PlannedTask array{id: string|null, title: string, description: string, steps: list<string>, target_data: string, impact_summary: string}
 */
final readonly class WorkflowEditor
{
    private const MAX_TASKS = 10;

    private const TITLE_LIMIT = 200;

    private const CHANGE_TASK = 'task';

    private const CHANGE_TITLE = 'title';

    public function __construct(
        private AuditAvailability $availability,
        private AuditLogger $audit,
        private WorkflowTransition $transition,
        private WorkflowRevisions $revisions,
        private InputScanner $scanner,
        private ScanRecorder $recorder,
    ) {}

    /**
     * The title is not part of the plan, so there is no new revision and the state stays. It is still
     * refused while the workflow cannot be edited, and it is text like any other: it is scanned and masked.
     *
     * @throws InputBlockedException
     * @throws ValidationException when masking made it too long
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function updateTitle(User $user, Workflow $workflow, int $expectedRevisionNo, string $title): void
    {
        $this->availability->assertAvailable();
        $this->assertEditable($workflow, $expectedRevisionNo);

        $result = $this->scanner->scanFields([PlanText::TITLE_FIELD => $title]);
        $this->refuseBlocked($user, SecurityScan::TARGET_INPUT, $workflow->id, $result);

        $masked = ($result->maskedFields ?? [])[PlanText::TITLE_FIELD];

        if (mb_strlen($masked, 'UTF-8') > self::TITLE_LIMIT) {
            throw self::tooLong([PlanText::TITLE_FIELD]);
        }

        SingleAttemptTransaction::run(DB::connection(), function () use ($user, $workflow, $expectedRevisionNo, $masked, $result): void {
            $locked = $this->lockAtRevision($workflow, $expectedRevisionNo);
            WorkflowStateMachine::next($locked->status, WorkflowEvent::Edit);

            $this->recorder->record($user, SecurityScan::TARGET_INPUT, $locked->id, $result);

            $locked->forceFill([
                'title' => $masked,
                'lock_version' => $locked->lock_version + 1,
                'max_severity' => self::raisedSeverity($locked, $result),
            ])->save();

            $this->recordUpdate($user, $locked, $expectedRevisionNo, self::CHANGE_TITLE);
        });
    }

    /**
     * @param  array<string, mixed>  $fields
     *
     * @throws InputBlockedException
     * @throws ValidationException when masking made a text too long
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function updateTask(User $user, Workflow $workflow, WorkflowTask $task, int $expectedRevisionNo, array $fields): void
    {
        $this->change(
            $user,
            $workflow,
            $expectedRevisionNo,
            fn (array $plan) => array_map(fn (array $planned) => $planned['id'] === $task->id ? self::planned($task->id, $fields) : $planned, $plan),
            function () use ($task, $fields): void {
                $task->forceFill([
                    'action_type' => $fields['action_type'],
                    'priority' => $fields['priority'],
                    ...WorkflowRevisions::derived((string) $fields['action_type']),
                ])->save();
            },
        );
    }

    /**
     * @param  array<string, mixed>  $fields
     *
     * @throws InputBlockedException
     * @throws ValidationException when the workflow already has the most tasks it can have, or masking made a text too long
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function addTask(User $user, Workflow $workflow, int $expectedRevisionNo, array $fields): void
    {
        $this->change(
            $user,
            $workflow,
            $expectedRevisionNo,
            function (array $plan) use ($fields): array {
                if (count($plan) >= self::MAX_TASKS) {
                    throw ValidationException::withMessages(['tasks' => ['タスクは10件までです。']]);
                }

                return [...$plan, self::planned(null, $fields)];
            },
            function (Workflow $locked, array $masked) use ($fields): void {
                $added = $masked[count($masked) - 1];

                (new WorkflowTask)->forceFill([
                    ...self::textOf($added),
                    'action_type' => $fields['action_type'],
                    'priority' => $fields['priority'],
                    ...WorkflowRevisions::derived((string) $fields['action_type']),
                    'workflow_id' => $locked->id,
                    'position' => (int) WorkflowTask::query()->where('workflow_id', $locked->id)->max('position') + 1,
                    'ai_claimed_permissions' => [],
                ])->save();
            },
        );
    }

    /**
     * @throws InputBlockedException
     * @throws ValidationException when it is the last task
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function deleteTask(User $user, Workflow $workflow, WorkflowTask $task, int $expectedRevisionNo): void
    {
        $this->change(
            $user,
            $workflow,
            $expectedRevisionNo,
            function (array $plan) use ($task): array {
                if (count($plan) <= 1) {
                    throw ValidationException::withMessages(['tasks' => ['タスクは1件以上必要です。']]);
                }

                return array_values(array_filter($plan, fn (array $planned) => $planned['id'] !== $task->id));
            },
            function (Workflow $locked) use ($task): void {
                $position = $task->position;
                $task->delete();

                WorkflowTask::query()
                    ->where('workflow_id', $locked->id)
                    ->where('position', '>', $position)
                    ->decrement('position');
            },
        );
    }

    /**
     * Back to Draft in a new revision. The plan does not change, but the scan is made again: a new revision needs
     * one, and the rules may be newer than the ones that passed it (docs/security-design.md §9.3).
     *
     * @throws InputBlockedException
     * @throws ValidationException when masking made a text too long
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function reopen(User $user, Workflow $workflow): void
    {
        $revisionNo = (int) WorkflowRevision::query()->whereKey($workflow->current_revision_id)->value('revision_no');

        $this->change($user, $workflow, $revisionNo, fn (array $plan) => $plan, function (): void {}, WorkflowEvent::Reopen);
    }

    /**
     * @param  Closure(list<PlannedTask>): list<PlannedTask>  $propose  The plan as this change would make it.
     * @param  Closure(Workflow, list<PlannedTask>): void  $apply
     */
    private function change(User $user, Workflow $workflow, int $expectedRevisionNo, Closure $propose, Closure $apply, WorkflowEvent $event = WorkflowEvent::Edit): void
    {
        $this->availability->assertAvailable();
        $this->assertEditable($workflow, $expectedRevisionNo, $event);

        $plan = $propose($this->currentPlan($workflow));
        $result = $this->scanner->scanFields(PlanText::fields(array_map(self::textOf(...), $plan)));
        $this->refuseBlocked($user, SecurityScan::TARGET_REVISION, null, $result);

        $maskedFields = $result->maskedFields ?? [];
        $tooLong = PlanText::tooLong($maskedFields);

        if ($tooLong !== []) {
            throw self::tooLong($tooLong);
        }

        $masked = array_map(
            fn (array $planned, array $text) => ['id' => $planned['id'], ...$text],
            $plan,
            PlanText::withMasked(array_map(self::textOf(...), $plan), $maskedFields),
        );

        SingleAttemptTransaction::run(DB::connection(), function () use ($user, $workflow, $expectedRevisionNo, $apply, $masked, $result, $event): void {
            $locked = $this->lockAtRevision($workflow, $expectedRevisionNo);

            $this->transition->apply($locked, $event);
            $apply($locked, $masked);
            $this->writeMasked($masked);

            $revisionNo = $expectedRevisionNo + 1;
            $revisionId = (string) Str::uuid7();
            $scan = $this->recorder->record($user, SecurityScan::TARGET_REVISION, $revisionId, $result);
            $changeType = $event === WorkflowEvent::Reopen ? WorkflowRevisions::CHANGE_REOPEN : WorkflowRevisions::CHANGE_USER_EDIT;
            $revision = $this->revisions->record($revisionId, $locked, $revisionNo, $changeType, $user, $scan);

            $locked->forceFill([
                'current_revision_id' => $revision->id,
                'max_severity' => self::raisedSeverity($locked, $result),
            ])->save();

            if ($event === WorkflowEvent::Reopen) {
                $this->audit->recordInTransaction(
                    AuditEntry::byUserOn(AuditEventType::WorkflowReopened, $user, 'workflow', $locked->id, ['revision_no' => $revisionNo]),
                    'workflow_reopened_unrecorded',
                );
            } else {
                $this->recordUpdate($user, $locked, $revisionNo, self::CHANGE_TASK);
            }
        });
    }

    /**
     * @return list<PlannedTask>
     */
    private function currentPlan(Workflow $workflow): array
    {
        return array_values(WorkflowTask::query()
            ->where('workflow_id', $workflow->id)
            ->orderBy('position')
            ->get()
            ->map(fn (WorkflowTask $task) => self::planned($task->id, $task->only(['title', 'description', 'steps', 'target_data', 'impact_summary'])))
            ->all());
    }

    /**
     * Every task of the plan holds what was scanned, including older tasks that had personal data in them.
     *
     * @param  list<PlannedTask>  $masked
     */
    private function writeMasked(array $masked): void
    {
        foreach ($masked as $planned) {
            if ($planned['id'] !== null) {
                WorkflowTask::query()->whereKey($planned['id'])->firstOrFail()->forceFill(self::textOf($planned))->save();
            }
        }
    }

    /**
     * @param  array<string, mixed>  $fields
     * @return PlannedTask
     */
    private static function planned(?string $id, array $fields): array
    {
        /** @var list<string> $steps */
        $steps = array_values((array) $fields['steps']);

        return [
            'id' => $id,
            'title' => (string) $fields['title'],
            'description' => (string) $fields['description'],
            'steps' => $steps,
            'target_data' => (string) $fields['target_data'],
            'impact_summary' => (string) $fields['impact_summary'],
        ];
    }

    /**
     * @param  PlannedTask  $planned
     * @return array{title: string, description: string, steps: list<string>, target_data: string, impact_summary: string}
     */
    private static function textOf(array $planned): array
    {
        return [
            'title' => $planned['title'],
            'description' => $planned['description'],
            'steps' => $planned['steps'],
            'target_data' => $planned['target_data'],
            'impact_summary' => $planned['impact_summary'],
        ];
    }

    /**
     * A stop keeps its scan and audit record, and changes nothing else.
     *
     * @throws InputBlockedException
     */
    private function refuseBlocked(User $user, string $targetType, ?string $targetId, InputScanResult $result): void
    {
        if ($result->blocks()) {
            SingleAttemptTransaction::run(DB::connection(), fn () => $this->recorder->record($user, $targetType, $targetId, $result));

            throw new InputBlockedException($result);
        }
    }

    /**
     * It only goes up. Removing what was found afterwards does not undo that it was there, so the approver
     * still has to confirm the risk (docs/security-design.md §3.5).
     */
    private static function raisedSeverity(Workflow $workflow, InputScanResult $result): ?string
    {
        $current = $workflow->max_severity === null ? null : Severity::from($workflow->max_severity);

        return Severity::higher($current, $result->maxSeverity)?->value;
    }

    /**
     * @param  list<string>  $fields
     */
    private static function tooLong(array $fields): ValidationException
    {
        return ValidationException::withMessages(array_fill_keys($fields, ['マスキング後の文字数が上限を超えます。短くしてください。']));
    }

    /**
     * Before any scan, so that a request that is going to be refused anyway leaves no record of one.
     *
     * @throws WorkflowConflictException
     */
    private function assertEditable(Workflow $workflow, int $expectedRevisionNo, WorkflowEvent $event = WorkflowEvent::Edit): void
    {
        $current = WorkflowRevision::query()->whereKey($workflow->current_revision_id)->value('revision_no');

        if ($current !== $expectedRevisionNo) {
            throw WorkflowConflictException::revisionConflict();
        }

        WorkflowStateMachine::next($workflow->status, $event);
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
