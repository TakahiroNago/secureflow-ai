<?php

namespace App\Http\Middleware;

use App\Domain\Auth\RetiredSessions;
use Closure;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel ends every request by saving the session and sending its cookie, under the id the request
 * started with. A request still running when that id was retired does neither: it would bring back a
 * session that a logout ended, or replace the browser's new cookie with the old one.
 *
 * The check before saving is for the store's benefit. What makes it safe is the write itself, see
 * RetirementAwareSessionHandler. The cookie comes last, so it is decided on what actually happened.
 */
final class StartSessionUnlessRetired extends StartSession
{
    protected function handleStatefulRequest(Request $request, $session, Closure $next)
    {
        $request->setLaravelSession($this->startSession($request, $session));

        $this->collectGarbage($session);

        $response = $next($request);

        $this->storeCurrentUrl($request, $session);

        if ($this->isRetired($session)) {
            return $this->withoutSessionCookies($response);
        }

        $this->saveSession($request);

        if ($this->isRetired($session)) {
            return $this->withoutSessionCookies($response);
        }

        $this->addCookieToResponse($response, $session);

        return $response;
    }

    private function isRetired(Session $session): bool
    {
        return app(RetiredSessions::class)->isRetired($session->getId());
    }

    /**
     * The CSRF cookie carries the token of the session this request read, which is no longer anyone's.
     */
    private function withoutSessionCookies(Response $response): Response
    {
        $config = $this->manager->getSessionConfig();

        $response->headers->removeCookie('XSRF-TOKEN', $config['path'], $config['domain']);

        return $response;
    }
}
