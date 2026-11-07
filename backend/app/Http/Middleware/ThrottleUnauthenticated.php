<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The limit for those with no session, by address (docs/api-design.md §1.4). It is the first thing in the api group:
 * Sanctum's stack and authentication turn these away before the limit for a user could count them. Only a failed authentication counts, and only
 * that is replaced, so a logged-in user behind the same address is not stopped by someone else's requests.
 */
final readonly class ThrottleUnauthenticated
{
    private const PER_MINUTE = 60;

    public function __construct(private RateLimiter $limiter) {}

    /**
     * Authentication can end in an exception, or in an answer that already holds one: both count.
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            $response = $next($request);
        } catch (AuthenticationException $exception) {
            $this->count($request);

            throw $exception;
        }

        if (property_exists($response, 'exception') && $response->exception instanceof AuthenticationException) {
            $this->count($request);
        }

        return $response;
    }

    /**
     * @throws ThrottleRequestsException once the address has used up its minute
     */
    private function count(Request $request): void
    {
        $key = 'unauthenticated|'.hash('sha256', (string) $request->ip());

        if ($this->limiter->tooManyAttempts($key, self::PER_MINUTE)) {
            throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $this->limiter->availableIn($key)]);
        }

        $this->limiter->hit($key);
    }
}
