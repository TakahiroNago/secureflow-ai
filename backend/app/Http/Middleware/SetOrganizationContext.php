<?php

namespace App\Http\Middleware;

use App\Models\User;
use App\Support\Organization\OrganizationContext;
use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Runs before route model binding (bootstrap/app.php), so that binding is already scoped.
 */
final class SetOrganizationContext
{
    public function __construct(private readonly OrganizationContext $context) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (! $user instanceof User) {
            throw new AuthenticationException;
        }

        $this->context->set($user->organization_id);

        return $next($request);
    }
}
