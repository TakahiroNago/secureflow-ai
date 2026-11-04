<?php

namespace App\Http\Middleware;

use App\Support\Http\ProblemDetails;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * docs/api-design.md §1: a request body must be JSON, anything else is 415.
 */
final class RequireJsonBody
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if ($request->getContent() !== '' && ! $request->isJson()) {
            return ProblemDetails::response(415, 'UNSUPPORTED_MEDIA_TYPE', 'Unsupported media type', 'Content-Type は application/json を指定してください。');
        }

        return $next($request);
    }
}
