<?php

namespace App\Policies;

use App\Models\AiAnalysisRequest;
use App\Models\User;
use Illuminate\Auth\Access\Response;

/**
 * docs/api-design.md §3.3: an analysis is visible to the person who asked for it, and to nobody else,
 * including an admin. Everyone else gets the same 404 as for one that does not exist.
 */
final class AnalysisPolicy
{
    public function view(User $user, AiAnalysisRequest $analysis): Response
    {
        if (! $user->is_active) {
            return Response::deny('Not allowed.', 'FORBIDDEN');
        }

        return $user->organization_id === $analysis->organization_id && $user->id === $analysis->user_id
            ? Response::allow()
            : Response::denyAsNotFound();
    }
}
