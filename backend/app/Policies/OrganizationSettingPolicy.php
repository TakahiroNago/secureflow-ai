<?php

namespace App\Policies;

use App\Models\User;
use Illuminate\Auth\Access\Response;

/**
 * docs/api-design.md §2 and §3.9. Settings are read and changed by an admin only. There is one row per
 * organization, and the organization comes from the session, so there is no resource to check here.
 */
final class OrganizationSettingPolicy
{
    private const ROLE_ADMIN = 'admin';

    public function view(User $user): Response
    {
        return $this->admin($user);
    }

    public function update(User $user): Response
    {
        return $this->admin($user);
    }

    private function admin(User $user): Response
    {
        return $user->is_active && $user->role === self::ROLE_ADMIN
            ? Response::allow()
            : Response::deny('Not allowed.', 'FORBIDDEN');
    }
}
