<?php

namespace App\Policies;

use App\Models\SecurityScan;
use App\Models\User;
use Illuminate\Auth\Access\Response;

/**
 * docs/api-design.md §3.7. A scan is seen by whoever may see what it scanned: an admin and an auditor see the
 * organization's, a member only their own, and another member's answers 404 so that it is not revealed.
 */
final class SecurityScanPolicy
{
    private const ROLES_SEEING_ORGANIZATION = ['admin', 'auditor'];

    public function view(User $user, SecurityScan $scan): Response
    {
        if (! $user->is_active) {
            return Response::deny('Not allowed.', 'FORBIDDEN');
        }

        if ($user->organization_id !== $scan->organization_id) {
            return Response::denyAsNotFound();
        }

        $seesOrganization = in_array($user->role, self::ROLES_SEEING_ORGANIZATION, true);

        return $seesOrganization || $scan->user_id === $user->id ? Response::allow() : Response::denyAsNotFound();
    }
}
