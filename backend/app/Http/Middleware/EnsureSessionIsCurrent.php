<?php

namespace App\Http\Middleware;

use App\Domain\Auth\AuthenticatedSession;
use App\Models\User;
use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Runs after auth:sanctum on every protected route. It ends the session when the user was disabled
 * (is_active = false), the absolute limit passed, or the password changed in another session.
 * An account lock is deliberately not a reason: see docs/security-design.md §12.
 */
final class EnsureSessionIsCurrent
{
    public function __construct(private readonly AuthenticatedSession $session) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user instanceof User || ! $request->hasSession() || ! $this->session->isCurrent($request, $user)) {
            if ($request->hasSession()) {
                $this->session->end($request);
            }

            throw new AuthenticationException;
        }

        return $next($request);
    }
}
