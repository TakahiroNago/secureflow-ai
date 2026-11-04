<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Session\TokenMismatchException;
use Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful;
use Symfony\Component\HttpFoundation\Response;

/**
 * Login needs a session, and only an allowed frontend origin gets one and passes the CSRF check.
 * Any other origin is answered like a failed CSRF check (419).
 */
final class RequireStatefulFrontend
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! EnsureFrontendRequestsAreStateful::fromFrontend($request)) {
            throw new TokenMismatchException('The request does not come from an allowed frontend.');
        }

        return $next($request);
    }
}
