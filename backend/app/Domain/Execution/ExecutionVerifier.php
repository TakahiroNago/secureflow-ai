<?php

namespace App\Domain\Execution;

use App\Domain\Workflow\ApprovalEligibility;
use App\Domain\Workflow\WorkflowStatus;
use App\Models\Approval;
use App\Models\Workflow;
use App\Models\WorkflowExecution;
use App\Models\WorkflowRevision;
use App\Models\WorkflowTask;
use App\Security\Policy\ActionCatalog;
use App\Security\Scanning\ScanDecision;
use Illuminate\Database\Eloquent\Collection;

/**
 * Everything that must still be true at the moment of running (docs/security-design.md §10). Who is asking is the
 * policy's part, and the key is ExecutionService's. Whether an approval is valid is calculated here, never stored.
 */
final class ExecutionVerifier
{
    public const EXECUTION_ALREADY_EXISTS = 'EXECUTION_ALREADY_EXISTS';

    public const APPROVAL_NOT_VALID = 'APPROVAL_NOT_VALID';

    public const POLICY_FORBIDDEN = 'POLICY_FORBIDDEN';

    public const POLICY_VERSION_CHANGED = 'POLICY_VERSION_CHANGED';

    /**
     * The reason this plan cannot run, or null.
     *
     * @param  Collection<int, WorkflowTask>  $tasks
     */
    public static function refusal(Workflow $workflow, ?WorkflowRevision $revision, ?Approval $approval, Collection $tasks): ?string
    {
        if (self::alreadyRun($workflow, $approval)) {
            return self::EXECUTION_ALREADY_EXISTS;
        }

        if ($workflow->status !== WorkflowStatus::Approved || $revision === null || ! self::approvalIsValid($workflow, $revision, $approval)) {
            return self::APPROVAL_NOT_VALID;
        }

        if (! in_array($revision->scan_decision, [ScanDecision::Allow->value, ScanDecision::Warn->value], true)) {
            return $revision->scan_decision === ScanDecision::Block->value ? ApprovalEligibility::SCAN_BLOCKED : ApprovalEligibility::SCAN_REQUIRED;
        }

        if (ApprovalEligibility::hasForbiddenAction($tasks)) {
            return self::POLICY_FORBIDDEN;
        }

        if ($revision->policy_version !== ActionCatalog::VERSION) {
            return self::POLICY_VERSION_CHANGED;
        }

        return ApprovalEligibility::planIsIntact($workflow, $revision, $tasks) ? null : ApprovalEligibility::PLAN_HASH_MISMATCH;
    }

    private static function alreadyRun(Workflow $workflow, ?Approval $approval): bool
    {
        return WorkflowExecution::query()
            ->where('workflow_id', $workflow->id)
            ->where(fn ($query) => $query
                ->whereIn('status', [WorkflowExecution::STATUS_QUEUED, WorkflowExecution::STATUS_RUNNING])
                ->when($approval !== null, fn ($inner) => $inner->orWhere('approval_id', $approval?->id)))
            ->exists();
    }

    /**
     * Someone who has since been deactivated still made this decision, so it stands. That they were not the creator
     * is checked again, because everything else here relies on it.
     */
    private static function approvalIsValid(Workflow $workflow, WorkflowRevision $revision, ?Approval $approval): bool
    {
        return $approval !== null
            && $approval->decision === Approval::APPROVED
            && $approval->workflow_revision_id === $workflow->current_revision_id
            && $approval->decided_by !== $workflow->created_by
            && hash_equals($revision->plan_hash, $approval->plan_hash);
    }
}
