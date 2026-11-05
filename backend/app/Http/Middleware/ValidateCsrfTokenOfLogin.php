<?php

namespace App\Http\Middleware;

use App\Domain\Auth\AuthenticatedSession;
use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Http\Request;

/**
 * An ended or expired session is 401 on every route that needs a login, not 419 on the ones that
 * change something: there is nobody for a forged request to act as, and the client needs to log in,
 * not to reload a token. Everything with a login, and the login route itself, is checked as usual.
 */
final class ValidateCsrfTokenOfLogin extends ValidateCsrfToken
{
    /**
     * @param  Request  $request
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if ($this->routeNeedsLogin($request) && ! AuthenticatedSession::hasLogin($request)) {
            throw new AuthenticationException;
        }

        return parent::handle($request, $next);
    }

    private function routeNeedsLogin(Request $request): bool
    {
        return in_array('auth:sanctum', $request->route()?->gatherMiddleware() ?? [], true);
    }
}
