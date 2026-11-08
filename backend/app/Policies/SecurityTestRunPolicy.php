<?php

namespace App\Policies;

use App\Models\SecurityTestRun;
use App\Models\User;
use Illuminate\Auth\Access\Response;

/**
 * docs/api-design.md §2. Everyone in the organization reads the results; only an admin starts a run.
 */
final class SecurityTestRunPolicy
{
    private const ROLE_ADMIN = 'admin';

    public function viewAny(User $user): Response
    {
        return $user->is_active ? Response::allow() : $this->forbidden();
    }

    public function view(User $user, SecurityTestRun $run): Response
    {
        if ($user->organization_id !== $run->organization_id) {
            return Response::denyAsNotFound();
        }

        return $user->is_active ? Response::allow() : $this->forbidden();
    }

    public function create(User $user): Response
    {
        return $user->is_active && $user->role === self::ROLE_ADMIN ? Response::allow() : $this->forbidden();
    }

    private function forbidden(): Response
    {
        return Response::deny('Not allowed.', 'FORBIDDEN');
    }
}
