<?php

namespace App\Audit;

use App\Models\User;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Throwable;

/**
 * authz.denied and rate_limit.exceeded (docs/security-design.md §16.1, §16.7). At most one record per actor, route and
 * status in a minute reaches the chain: asking for what does not exist costs nothing, and would otherwise fill it. The
 * rest only count in the log. What is kept is the name of the route, never an id or any other part of the request.
 *
 * It changes no response, whatever happens here.
 */
final readonly class RefusalRecorder
{
    private const WINDOW_SECONDS = 60;

    private const LOG_EVERY = 100;

    private const FORBIDDEN = 403;

    private const NOT_FOUND = 404;

    private const AUTHENTICATED = 'auth:sanctum';

    private const OWN_RECORD_PREFIX = 'denied.attempt:';

    public function __construct(private AuditLogger $audit, private AuditAvailability $availability) {}

    public function note(Throwable $exception, Request $request): void
    {
        try {
            $route = $request->route();

            // Nothing else is looked at for any other error: during an outage this must not touch the database.
            if ($route instanceof Route && $route->getName() !== null && self::isRefusal($exception) && ! $this->availability->dbFlagged()) {
                $this->noteOn($exception, $request, $route, $route->getName());
            }
        } catch (Throwable $failure) {
            Log::warning('audit.refusal_not_recorded', ['metric' => 'audit.refusal_not_recorded', 'exception' => $failure::class]);
        }
    }

    private static function isRefusal(Throwable $exception): bool
    {
        return $exception instanceof ThrottleRequestsException
            || ($exception instanceof HttpExceptionInterface && in_array($exception->getStatusCode(), [self::FORBIDDEN, self::NOT_FOUND], true));
    }

    private function noteOn(Throwable $exception, Request $request, Route $route, string $name): void
    {
        $user = in_array(self::AUTHENTICATED, $route->gatherMiddleware(), true) ? $request->user() : null;

        if ($exception instanceof ThrottleRequestsException) {
            $this->rateLimited($request, $user instanceof User ? $user : null, $name);

            return;
        }

        if (! $user instanceof User || ! $exception instanceof HttpExceptionInterface) {
            return;
        }

        $status = $exception->getStatusCode();

        if ($status === self::NOT_FOUND || ($status === self::FORBIDDEN && ! $this->hasItsOwnRecord($route))) {
            if ($this->isFirstInWindow(AuditEventType::AuthzDenied, $user->id, $name, $status)) {
                $this->audit->recordAfterTransaction(
                    AuditEntry::byUser(AuditEventType::AuthzDenied, $user, 'denied', ['route' => $name, 'status' => $status]),
                    'authz_denied_unrecorded',
                );
            }
        }
    }

    /**
     * Someone with no session goes on the system chain, under its overall limit, by address. A login names an
     * email address in its request, which is not kept in any form (docs/security-design.md §16.2).
     */
    private function rateLimited(Request $request, ?User $user, string $name): void
    {
        if (! $this->isFirstInWindow(AuditEventType::RateLimitExceeded, $user->id ?? (string) $request->ip(), $name, 429)) {
            return;
        }

        $entry = $user === null
            ? AuditEntry::anonymous(AuditEventType::RateLimitExceeded, null, 'denied', ['route' => $name])
            : AuditEntry::byUser(AuditEventType::RateLimitExceeded, $user, 'denied', ['route' => $name]);

        $this->audit->recordAfterTransaction($entry, 'rate_limit_exceeded_unrecorded');
    }

    /**
     * These routes already record a refusal of the policy as approval.denied or execution.denied. A 404 they do not.
     */
    private function hasItsOwnRecord(Route $route): bool
    {
        foreach ($route->gatherMiddleware() as $middleware) {
            if (is_string($middleware) && str_starts_with($middleware, self::OWN_RECORD_PREFIX)) {
                return true;
            }
        }

        return false;
    }

    private function isFirstInWindow(AuditEventType $type, string $actor, string $route, int $status): bool
    {
        $window = (int) floor(now()->getTimestamp() / self::WINDOW_SECONDS);
        $key = 'audit:refusal:'.$window.':'.hash('sha256', implode('|', [$type->value, $actor, $route, $status]));

        Cache::add($key, 0, self::WINDOW_SECONDS * 2);
        $count = (int) Cache::increment($key);

        if ($count > 1 && ($count === 2 || $count % self::LOG_EVERY === 0)) {
            Log::info('audit.refusal_aggregated', ['metric' => 'audit.refusal_aggregated', 'event_type' => $type->value, 'route' => $route, 'count' => $count]);
        }

        return $count === 1;
    }
}
