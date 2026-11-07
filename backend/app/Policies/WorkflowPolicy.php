<?php

namespace App\Policies;

use App\Models\User;
use App\Models\Workflow;
use Illuminate\Auth\Access\Response;

/**
 * docs/api-design.md §2, docs/security-design.md §9.3 and §13. Another organization's workflow, and
 * another member's, answer 404 so that their existence is not revealed. A missing role answers 403.
 *
 * The role comes before ownership: a creator who became an auditor can no longer change anything.
 * A lock (locked_until) changes nothing here (§12).
 */
final class WorkflowPolicy
{
    private const ROLE_ADMIN = 'admin';

    private const ROLE_AUDITOR = 'auditor';

    public function viewAny(User $user): Response
    {
        return $user->is_active ? Response::allow() : $this->forbidden();
    }

    public function view(User $user, Workflow $workflow): Response
    {
        return $this->visibility($user, $workflow) ?? Response::allow();
    }

    public function create(User $user): Response
    {
        return $user->is_active && $user->role !== self::ROLE_AUDITOR ? Response::allow() : $this->forbidden();
    }

    public function update(User $user, Workflow $workflow): Response
    {
        return $this->ownerOnly($user, $workflow);
    }

    public function submit(User $user, Workflow $workflow): Response
    {
        return $this->ownerOnly($user, $workflow);
    }

    public function reopen(User $user, Workflow $workflow): Response
    {
        return $this->ownerOnly($user, $workflow);
    }

    public function approve(User $user, Workflow $workflow): Response
    {
        return $this->decide($user, $workflow);
    }

    public function reject(User $user, Workflow $workflow): Response
    {
        return $this->decide($user, $workflow);
    }

    /**
     * The list of what waits for a decision. A creator's own is listed too, marked as theirs to wait on.
     */
    public function viewApprovals(User $user): Response
    {
        return $user->is_active && $user->role === self::ROLE_ADMIN ? Response::allow() : $this->forbidden();
    }

    /**
     * An admin, or the owner to see only. An auditor reads the workflow and its history instead.
     */
    public function viewApprovalContext(User $user, Workflow $workflow): Response
    {
        $hidden = $this->visibility($user, $workflow);

        if ($hidden !== null) {
            return $hidden;
        }

        return $user->role === self::ROLE_AUDITOR ? $this->forbidden() : Response::allow();
    }

    public function execute(User $user, Workflow $workflow): Response
    {
        $hidden = $this->visibility($user, $workflow);

        if ($hidden !== null) {
            return $hidden;
        }

        return $user->role === self::ROLE_AUDITOR ? $this->forbidden() : Response::allow();
    }

    private function ownerOnly(User $user, Workflow $workflow): Response
    {
        $hidden = $this->visibility($user, $workflow);

        if ($hidden !== null) {
            return $hidden;
        }

        return $user->role !== self::ROLE_AUDITOR && $workflow->created_by === $user->id ? Response::allow() : $this->forbidden();
    }

    private function decide(User $user, Workflow $workflow): Response
    {
        $hidden = $this->visibility($user, $workflow);

        if ($hidden !== null) {
            return $hidden;
        }

        if ($user->role !== self::ROLE_ADMIN) {
            return Response::deny('Only an admin can decide.', 'APPROVER_ROLE_REQUIRED');
        }

        return $workflow->created_by === $user->id
            ? Response::deny('The creator cannot decide.', 'SELF_APPROVAL_FORBIDDEN')
            : Response::allow();
    }

    /**
     * Null when the user may know the workflow exists.
     */
    private function visibility(User $user, Workflow $workflow): ?Response
    {
        if (! $user->is_active) {
            return $this->forbidden();
        }

        if ($user->organization_id !== $workflow->organization_id) {
            return Response::denyAsNotFound();
        }

        $seesOrganization = in_array($user->role, [self::ROLE_ADMIN, self::ROLE_AUDITOR], true);

        return $seesOrganization || $workflow->created_by === $user->id ? null : Response::denyAsNotFound();
    }

    private function forbidden(): Response
    {
        return Response::deny('Not allowed.', 'FORBIDDEN');
    }
}
