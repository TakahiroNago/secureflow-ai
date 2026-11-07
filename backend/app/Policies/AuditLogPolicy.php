<?php

namespace App\Policies;

use App\Models\User;
use Illuminate\Auth\Access\Response;

/**
 * docs/api-design.md §2. An admin and an auditor read and verify their organization's log. A verification changes
 * nothing, so an auditor may run it. Nobody can change the log through the application.
 */
final class AuditLogPolicy
{
    public const ROLES = ['admin', 'auditor'];

    public function viewAny(User $user): Response
    {
        return $this->allowed($user);
    }

    public function verify(User $user): Response
    {
        return $this->allowed($user);
    }

    private function allowed(User $user): Response
    {
        return $user->is_active && in_array($user->role, self::ROLES, true)
            ? Response::allow()
            : Response::deny('Not allowed.', 'FORBIDDEN');
    }
}
