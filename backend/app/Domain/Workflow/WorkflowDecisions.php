<?php

namespace App\Domain\Workflow;

use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Domain\Security\InputBlockedException;
use App\Domain\Security\ScanRecorder;
use App\Models\Approval;
use App\Models\SecurityScan;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowRevision;
use App\Models\WorkflowTask;
use App\Security\Scanning\InputScanner;
use App\Security\Scanning\InputScanResult;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\Access\Response;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

/**
 * Approving and rejecting (docs/api-design.md §3.5, docs/security-design.md §9.3, §11).
 *
 * A comment or reason is text like any other, so it is scanned and masked. A scan can take seconds, so it runs
 * before the lock, and everything is checked once before it (a request that is going to be refused leaves no scan
 * behind) and once again under the lock (nothing can change between that check and the commit).
 *
 * Only an approval needs the plan to be good. Rejecting has to stay possible for a plan that is not.
 */
final readonly class WorkflowDecisions
{
    private const TEXT_LIMIT = 1000;

    private const FIELD_COMMENT = 'comment';

    private const FIELD_REASON = 'reason';

    private const UNIQUE_VIOLATION = '23505';

    private const NOT_FOUND = 404;

    public function __construct(
        private AuditAvailability $availability,
        private AuditLogger $audit,
        private WorkflowTransition $transition,
        private InputScanner $scanner,
        private ScanRecorder $recorder,
        private DeniedAttempts $denials,
    ) {}

    /**
     * @throws AuthorizationException when the approver lost the right to decide while this ran
     * @throws InputBlockedException
     * @throws RiskAcknowledgementRequiredException
     * @throws ValidationException when masking made the comment too long
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function approve(User $user, Workflow $workflow, int $revisionNo, string $planHash, bool $acknowledgedRisks, ?string $comment): void
    {
        $this->decide($user, $workflow, WorkflowEvent::Approve, $revisionNo, $planHash, $acknowledgedRisks, self::FIELD_COMMENT, $comment);
    }

    /**
     * @throws AuthorizationException when the approver lost the right to decide while this ran
     * @throws InputBlockedException
     * @throws ValidationException when masking made the reason too long
     * @throws WorkflowConflictException
     * @throws ServiceUnavailableException
     */
    public function reject(User $user, Workflow $workflow, int $revisionNo, string $planHash, string $reason): void
    {
        $this->decide($user, $workflow, WorkflowEvent::Reject, $revisionNo, $planHash, false, self::FIELD_REASON, $reason);
    }

    public static function conflictFor(string $refusal): WorkflowConflictException
    {
        return match ($refusal) {
            ApprovalEligibility::SCAN_REQUIRED => WorkflowConflictException::scanRequired(),
            ApprovalEligibility::SCAN_BLOCKED => WorkflowConflictException::scanBlocked(),
            ApprovalEligibility::FORBIDDEN_ACTION_PRESENT => WorkflowConflictException::forbiddenActionPresent(),
            default => WorkflowConflictException::planHashMismatch(),
        };
    }

    private function decide(User $user, Workflow $workflow, WorkflowEvent $event, int $revisionNo, string $planHash, bool $acknowledgedRisks, string $field, ?string $text): void
    {
        try {
            $this->assertDecidable($workflow, $event, $revisionNo, $planHash, $acknowledgedRisks);
            $this->availability->assertAvailable();

            $result = $text === null ? null : $this->scan($user, $workflow, $field, $text);

            SingleAttemptTransaction::run(DB::connection(), function () use ($user, $workflow, $event, $revisionNo, $planHash, $acknowledgedRisks, $field, $result): void {
                $locked = Workflow::query()->whereKey($workflow->id)->lockForUpdate()->firstOrFail();
                $approver = User::query()->whereKey($user->id)->sharedLock()->firstOrFail();

                $this->assertStillMayDecide($approver, $locked, $event);

                $revision = $this->assertDecidable($locked, $event, $revisionNo, $planHash, $acknowledgedRisks);

                if ($result !== null) {
                    $this->recorder->record($approver, SecurityScan::TARGET_INPUT, $locked->id, $result);
                }

                $this->store($approver, $locked, $revision, $event, $acknowledgedRisks, $result?->maskedFields[$field] ?? null);
                $this->transition->apply($locked, $event);
            });
        } catch (AuthorizationException $exception) {
            $this->denials->record(AuditEventType::ApprovalDenied, $user, $workflow, (string) ($exception->response()->code() ?? 'FORBIDDEN'));

            throw $exception;
        } catch (WorkflowConflictException $exception) {
            if ($exception->problemCode === ApprovalEligibility::PLAN_HASH_MISMATCH) {
                $this->denials->record(AuditEventType::ApprovalDenied, $user, $workflow, ApprovalEligibility::PLAN_HASH_MISMATCH);
            }

            throw $exception;
        } catch (QueryException $exception) {
            // The lock makes this unreachable in the application. The constraint is what guarantees it.
            if ($exception->getCode() === self::UNIQUE_VIOLATION && str_contains($exception->getMessage(), 'approvals_revision_unique')) {
                throw WorkflowConflictException::alreadyDecided();
            }

            throw $exception;
        }
    }

    /**
     * Read under the lock: a role or an account can have changed since the route's policy looked. To a demoted admin
     * the policy hides the workflow, but they were allowed to see it when this began, so the answer is the 403 of
     * docs/security-design.md §11 rather than a 404.
     *
     * @throws AuthorizationException
     */
    private function assertStillMayDecide(User $approver, Workflow $workflow, WorkflowEvent $event): void
    {
        $answer = Gate::forUser($approver)->inspect($event->value, $workflow);

        if ($answer->status() === self::NOT_FOUND) {
            Response::deny('Only an admin can decide.', 'APPROVER_ROLE_REQUIRED')->authorize();
        }

        $answer->authorize();
    }

    /**
     * In this order so that each case gets its designed answer: an edit that came first is a changed plan even
     * though the state has also moved, and a second decision is "already decided" rather than a wrong state.
     *
     * @throws RiskAcknowledgementRequiredException
     * @throws WorkflowConflictException
     */
    private function assertDecidable(Workflow $workflow, WorkflowEvent $event, int $revisionNo, string $planHash, bool $acknowledgedRisks): WorkflowRevision
    {
        $revision = WorkflowRevision::query()->whereKey($workflow->current_revision_id)->first();

        if ($revision === null || $revision->revision_no !== $revisionNo || ! hash_equals($revision->plan_hash, $planHash)) {
            throw WorkflowConflictException::planHashMismatch();
        }

        if (Approval::query()->where('workflow_revision_id', $revision->id)->exists()) {
            throw WorkflowConflictException::alreadyDecided();
        }

        WorkflowStateMachine::next($workflow->status, $event);

        if ($event === WorkflowEvent::Approve) {
            $tasks = WorkflowTask::query()->where('workflow_id', $workflow->id)->orderBy('position')->get();
            $refusal = ApprovalEligibility::approvalRefusal($workflow, $revision, $tasks);

            if ($refusal !== null) {
                throw self::conflictFor($refusal);
            }

            if (ApprovalEligibility::requiresRiskAcknowledgement($workflow) && ! $acknowledgedRisks) {
                throw new RiskAcknowledgementRequiredException('Risk acknowledgement required');
            }
        }

        return $revision;
    }

    /**
     * @throws InputBlockedException
     * @throws ValidationException
     */
    private function scan(User $user, Workflow $workflow, string $field, string $text): InputScanResult
    {
        $result = $this->scanner->scanFields([$field => $text]);

        if ($result->blocks()) {
            SingleAttemptTransaction::run(DB::connection(), fn () => $this->recorder->record($user, SecurityScan::TARGET_INPUT, $workflow->id, $result));

            throw new InputBlockedException($result);
        }

        if (mb_strlen(($result->maskedFields ?? [])[$field] ?? '', 'UTF-8') > self::TEXT_LIMIT) {
            throw ValidationException::withMessages([$field => ['マスキング後の文字数が上限を超えます。短くしてください。']]);
        }

        return $result;
    }

    private function store(User $approver, Workflow $workflow, WorkflowRevision $revision, WorkflowEvent $event, bool $acknowledgedRisks, ?string $maskedText): void
    {
        $approved = $event === WorkflowEvent::Approve;

        (new Approval)->forceFill([
            'id' => (string) Str::uuid7(),
            'workflow_id' => $workflow->id,
            'workflow_revision_id' => $revision->id,
            'plan_hash' => $revision->plan_hash,
            'decision' => $approved ? Approval::APPROVED : Approval::REJECTED,
            'decided_by' => $approver->id,
            'comment' => $maskedText,
            'acknowledged_risks' => $acknowledgedRisks,
        ])->save();

        $this->audit->recordInTransaction(
            AuditEntry::byUserOn(
                $approved ? AuditEventType::ApprovalApproved : AuditEventType::ApprovalRejected,
                $approver,
                'workflow',
                $workflow->id,
                ['revision_no' => $revision->revision_no, 'plan_hash' => $revision->plan_hash],
            ),
            $approved ? 'approval_approved_unrecorded' : 'approval_rejected_unrecorded',
        );
    }
}
