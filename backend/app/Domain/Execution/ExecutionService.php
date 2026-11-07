<?php

namespace App\Domain\Execution;

use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Domain\Workflow\ApprovalEligibility;
use App\Domain\Workflow\DeniedAttempts;
use App\Domain\Workflow\WorkflowConflictException;
use App\Domain\Workflow\WorkflowEvent;
use App\Domain\Workflow\WorkflowTransition;
use App\Jobs\ExecuteWorkflowJob;
use App\Models\Approval;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowExecution;
use App\Models\WorkflowRevision;
use App\Models\WorkflowTask;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\Access\Response;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;

/**
 * Consumes an approval (docs/security-design.md §10, §11). The row, the state, the audit record and the job commit
 * together under the workflow's row lock, so an approval is never used up without a record of who used it.
 *
 * A resend of the same request comes first, because the state has moved by then: it has to get the first answer back
 * after a lost connection, not a refusal.
 */
final readonly class ExecutionService
{
    private const UNIQUE_VIOLATION = '23505';

    private const NOT_FOUND = 404;

    public function __construct(
        private AuditAvailability $availability,
        private AuditLogger $audit,
        private WorkflowTransition $transition,
        private DeniedAttempts $denials,
    ) {}

    /**
     * @throws AuthorizationException when the user lost the right to execute while this ran
     * @throws IdempotencyKeyReusedException
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function request(User $user, Workflow $workflow, string $key): WorkflowExecution
    {
        try {
            // Without the lock, so that a refusal does not depend on the audit log being available.
            $resent = $this->resent($user, $workflow, $key);

            if ($resent !== null) {
                return $resent;
            }

            $this->assertRunnable($workflow);
            $this->availability->assertAvailable();

            return SingleAttemptTransaction::run(DB::connection(), function () use ($user, $workflow, $key): WorkflowExecution {
                $locked = Workflow::query()->whereKey($workflow->id)->lockForUpdate()->firstOrFail();
                $resent = $this->resent($user, $locked, $key);

                if ($resent !== null) {
                    return $resent;
                }

                $executor = User::query()->whereKey($user->id)->sharedLock()->firstOrFail();
                $this->assertStillMayExecute($executor, $locked);

                return $this->start($executor, $locked, $this->assertRunnable($locked), $key);
            });
        } catch (AuthorizationException $exception) {
            $this->denials->record(AuditEventType::ExecutionDenied, $user, $workflow, (string) ($exception->response()->code() ?? 'FORBIDDEN'));

            throw $exception;
        } catch (ExecutionRefusedException $exception) {
            $this->denials->record(AuditEventType::ExecutionDenied, $user, $workflow, $exception->reason);

            throw self::conflictFor($exception->reason);
        } catch (IdempotencyKeyReusedException $exception) {
            $this->denials->record(AuditEventType::ExecutionDenied, $user, $workflow, 'IDEMPOTENCY_KEY_REUSED');

            throw $exception;
        } catch (QueryException $exception) {
            throw $this->fromConstraint($exception, $user, $workflow);
        }
    }

    /**
     * The row lock makes these unreachable for one workflow. A key used at the same moment on another one is not.
     */
    private function fromConstraint(QueryException $exception, User $user, Workflow $workflow): QueryException|WorkflowConflictException|IdempotencyKeyReusedException
    {
        if ($exception->getCode() !== self::UNIQUE_VIOLATION) {
            return $exception;
        }

        if (str_contains($exception->getMessage(), 'workflow_executions_idempotency_unique')) {
            $this->denials->record(AuditEventType::ExecutionDenied, $user, $workflow, 'IDEMPOTENCY_KEY_REUSED');

            return new IdempotencyKeyReusedException('Idempotency key reused');
        }

        if (str_contains($exception->getMessage(), 'workflow_executions_approval_unique') || str_contains($exception->getMessage(), 'workflow_executions_one_active_unique')) {
            $this->denials->record(AuditEventType::ExecutionDenied, $user, $workflow, ExecutionVerifier::EXECUTION_ALREADY_EXISTS);

            return self::conflictFor(ExecutionVerifier::EXECUTION_ALREADY_EXISTS);
        }

        return $exception;
    }

    /**
     * The same key is the same request only with the same approval, which belongs to one workflow, and the same person.
     *
     * @throws IdempotencyKeyReusedException
     */
    private function resent(User $user, Workflow $workflow, string $key): ?WorkflowExecution
    {
        $existing = WorkflowExecution::query()->where('idempotency_key', $key)->first();

        if ($existing === null) {
            return null;
        }

        $approvalId = Approval::query()->where('workflow_revision_id', $workflow->current_revision_id)->value('id');

        if ($existing->requested_by !== $user->id || $existing->approval_id !== $approvalId) {
            throw new IdempotencyKeyReusedException('Idempotency key reused');
        }

        return $existing;
    }

    /**
     * @throws ExecutionRefusedException
     */
    private function assertRunnable(Workflow $workflow): Approval
    {
        $revision = WorkflowRevision::query()->whereKey($workflow->current_revision_id)->first();
        $approval = Approval::query()->where('workflow_revision_id', $workflow->current_revision_id)->first();
        $tasks = WorkflowTask::query()->where('workflow_id', $workflow->id)->orderBy('position')->get();
        $refusal = ExecutionVerifier::refusal($workflow, $revision, $approval, $tasks);

        if ($refusal !== null || $approval === null) {
            throw new ExecutionRefusedException($refusal ?? ExecutionVerifier::APPROVAL_NOT_VALID);
        }

        return $approval;
    }

    /**
     * Read under the lock. The policy hides the workflow from someone demoted just now, but it was theirs to see when
     * this began, so the answer is a 403 rather than a 404 (docs/api-design.md §3.6).
     *
     * @throws AuthorizationException
     */
    private function assertStillMayExecute(User $executor, Workflow $workflow): void
    {
        $answer = Gate::forUser($executor)->inspect('execute', $workflow);

        if ($answer->status() === self::NOT_FOUND) {
            Response::deny('Not allowed.', 'FORBIDDEN')->authorize();
        }

        $answer->authorize();
    }

    private function start(User $executor, Workflow $workflow, Approval $approval, string $key): WorkflowExecution
    {
        $execution = new WorkflowExecution;
        $execution->forceFill([
            'id' => (string) Str::uuid7(),
            'workflow_id' => $workflow->id,
            'approval_id' => $approval->id,
            'workflow_revision_id' => $approval->workflow_revision_id,
            'idempotency_key' => $key,
            'requested_by' => $executor->id,
            'status' => WorkflowExecution::STATUS_QUEUED,
        ])->save();

        $this->transition->apply($workflow, WorkflowEvent::Execute);

        $this->audit->recordInTransaction(
            AuditEntry::byUserOn(AuditEventType::ExecutionStarted, $executor, 'workflow', $workflow->id, [
                'execution_id' => $execution->id,
                'revision_no' => (int) WorkflowRevision::query()->whereKey($approval->workflow_revision_id)->value('revision_no'),
            ]),
            'execution_started_unrecorded',
        );

        ExecuteWorkflowJob::dispatch($execution->id, $execution->organization_id);

        return $execution;
    }

    private static function conflictFor(string $reason): WorkflowConflictException
    {
        return match ($reason) {
            ExecutionVerifier::EXECUTION_ALREADY_EXISTS => WorkflowConflictException::executionAlreadyExists(),
            ExecutionVerifier::POLICY_FORBIDDEN => WorkflowConflictException::policyViolation(),
            ExecutionVerifier::POLICY_VERSION_CHANGED => WorkflowConflictException::policyVersionChanged(),
            ApprovalEligibility::SCAN_REQUIRED => WorkflowConflictException::scanRequired(),
            ApprovalEligibility::SCAN_BLOCKED => WorkflowConflictException::scanBlocked(),
            ApprovalEligibility::PLAN_HASH_MISMATCH => WorkflowConflictException::planHashMismatch(),
            default => WorkflowConflictException::approvalNotValid(),
        };
    }
}
