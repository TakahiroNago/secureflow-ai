<?php

namespace App\Http\Middleware;

use App\Audit\AuditAvailability;
use App\Domain\Auth\AuthenticatedSession;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Runs before auth:sanctum. A session with a login needs the users table on every request, so while
 * the database is known to be unavailable it gets 503 at once instead of waiting for a connection.
 * A request without a login needs no database and still gets its 401 (docs/security-design.md §16.5.1).
 */
final class RejectWhileDatabaseUnavailable
{
    public function __construct(private readonly AuditAvailability $availability) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (AuthenticatedSession::hasLogin($request)) {
            $this->availability->assertDatabaseUsable();
        }

        return $next($request);
    }
}
