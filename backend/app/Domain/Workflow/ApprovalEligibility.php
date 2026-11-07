<?php

namespace App\Domain\Workflow;

use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowRevision;
use App\Models\WorkflowTask;
use App\Security\Policy\PolicyDecision;
use App\Security\Scanning\ScanDecision;
use App\Security\Scanning\Severity;
use Illuminate\Database\Eloquent\Collection;

/**
 * Whether a plan can go forward (docs/security-design.md §9.3). One answer for the refusal and for what the screen
 * says beforehand. A missing scan is never read as allowed: rows from before step 2-3 have none.
 */
final class ApprovalEligibility
{
    public const SCAN_REQUIRED = 'SCAN_REQUIRED';

    public const SCAN_BLOCKED = 'SCAN_BLOCKED';

    public const FORBIDDEN_ACTION_PRESENT = 'FORBIDDEN_ACTION_PRESENT';

    public const PLAN_HASH_MISMATCH = 'PLAN_HASH_MISMATCH';

    public const SELF_CREATED = 'SELF_CREATED';

    public const ROLE_NOT_ADMIN = 'ROLE_NOT_ADMIN';

    public const INVALID_STATE = 'INVALID_STATE';

    private const ROLE_ADMIN = 'admin';

    /**
     * What stops this plan from being submitted, if anything.
     *
     * @param  Collection<int, WorkflowTask>  $tasks
     */
    public static function submissionRefusal(?WorkflowRevision $revision, Collection $tasks): ?string
    {
        return match (true) {
            $revision === null, $revision->scan_id === null, $revision->scan_decision === null => self::SCAN_REQUIRED,
            $revision->scan_decision === ScanDecision::Block->value => self::SCAN_BLOCKED,
            self::hasForbiddenAction($tasks) => self::FORBIDDEN_ACTION_PRESENT,
            default => null,
        };
    }

    /**
     * What stops this plan from being approved, if anything: the above, and that it is still what was recorded.
     *
     * @param  Collection<int, WorkflowTask>  $tasks
     */
    public static function approvalRefusal(Workflow $workflow, ?WorkflowRevision $revision, Collection $tasks): ?string
    {
        $refusal = self::submissionRefusal($revision, $tasks);

        if ($refusal !== null || $revision === null) {
            return $refusal;
        }

        return self::planIsIntact($workflow, $revision, $tasks) ? null : self::PLAN_HASH_MISMATCH;
    }

    /**
     * For the screen and the list. The server checks everything again on the decision itself.
     *
     * @param  Collection<int, WorkflowTask>  $tasks
     */
    public static function cannotApproveReason(User $viewer, Workflow $workflow, ?WorkflowRevision $revision, Collection $tasks): ?string
    {
        return match (true) {
            $viewer->role !== self::ROLE_ADMIN => self::ROLE_NOT_ADMIN,
            $workflow->created_by === $viewer->id => self::SELF_CREATED,
            $workflow->status !== WorkflowStatus::Pending => self::INVALID_STATE,
            default => self::approvalRefusal($workflow, $revision, $tasks),
        };
    }

    /**
     * Whatever was found at any time counts, even if the text has since been edited away, so an unknown value
     * also asks for the confirmation (docs/security-design.md §3.5).
     */
    public static function requiresRiskAcknowledgement(Workflow $workflow): bool
    {
        return $workflow->max_severity !== null && $workflow->max_severity !== Severity::Low->value;
    }

    /**
     * Someone other than the creator who could decide. A lock stops new logins only, so a locked admin counts.
     */
    public static function approverAvailable(Workflow $workflow): bool
    {
        return User::query()
            ->where('organization_id', $workflow->organization_id)
            ->where('role', self::ROLE_ADMIN)
            ->where('is_active', true)
            ->whereKeyNot($workflow->created_by)
            ->exists();
    }

    /**
     * The hash on the revision, its stored snapshot and the tasks the approver is shown must all be the same plan.
     * Comparing only with what the screen sent would not notice a row changed in the database.
     *
     * @param  Collection<int, WorkflowTask>  $tasks
     */
    public static function planIsIntact(Workflow $workflow, WorkflowRevision $revision, Collection $tasks): bool
    {
        if (! PlanHasher::matches($revision->plan_snapshot, $revision->plan_hash)) {
            return false;
        }

        try {
            return PlanHasher::matches(
                WorkflowRevisions::snapshotOf($workflow, $revision->revision_no, $revision->policy_version, $tasks),
                $revision->plan_hash,
            );
        } catch (InvalidPlanException) {
            return false;
        }
    }

    /**
     * As stored, and as the catalog says now: a policy can become stricter after the task was saved.
     *
     * @param  Collection<int, WorkflowTask>  $tasks
     */
    public static function hasForbiddenAction(Collection $tasks): bool
    {
        return $tasks->contains(fn (WorkflowTask $task) => $task->policy_decision !== PolicyDecision::Allowed->value
            || WorkflowRevisions::derived($task->action_type)['policy_decision'] !== PolicyDecision::Allowed->value);
    }
}
