<?php

namespace Tests\Support;

use Closure;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * For scripts/test-session-cookie-order.sh only, never registered by the application. It takes the place of
 * the outermost session middleware and holds a finished response: the session was saved and its cookie is on
 * the response, and nothing was sent yet. So the response reaches the client after whatever the script does
 * in the meantime, every time instead of sometimes.
 */
final class SessionRaceResponseHold
{
    public function __construct(private readonly EncryptCookies $cookies) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $this->cookies->handle($request, $next);

        SessionRaceSyncPoint::hold((string) $request->header('X-Test-Response-Hold'));

        return $response;
    }
}
