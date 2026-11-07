<?php

namespace App\Policies;

use App\Models\SecurityFinding;
use App\Models\User;
use Illuminate\Auth\Access\Response;

/**
 * docs/api-design.md §2. Everyone reads the findings of their own scans; an admin and an auditor read all of the
 * organization's. Only an admin changes a status. Which findings a member sees is decided by the query, not here:
 * the list is the only way to read them.
 */
final class SecurityFindingPolicy
{
    private const ROLE_ADMIN = 'admin';

    public function viewAny(User $user): Response
    {
        return $user->is_active ? Response::allow() : $this->forbidden();
    }

    public function update(User $user, SecurityFinding $finding): Response
    {
        if ($user->organization_id !== $finding->organization_id) {
            return Response::denyAsNotFound();
        }

        return $user->is_active && $user->role === self::ROLE_ADMIN ? Response::allow() : $this->forbidden();
    }

    private function forbidden(): Response
    {
        return Response::deny('Not allowed.', 'FORBIDDEN');
    }
}
