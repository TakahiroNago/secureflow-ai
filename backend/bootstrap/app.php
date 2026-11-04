<?php

use App\Http\Middleware\EnsureSessionIsCurrent;
use App\Http\Middleware\RequireJsonBody;
use App\Http\Middleware\RequireStatefulFrontend;
use App\Support\Http\ProblemDetails;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

// Without this, stack traces in the logs contain function arguments, which can include passwords.
ini_set('zend.exception_ignore_args', '1');

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        // The built-in "/up" health route is intentionally not registered.
        // Liveness / Readiness are defined in routes/api.php (docs/architecture.md §4.2).
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->statefulApi();
        // An API with no login page: answer 401 whatever the client accepts.
        $middleware->redirectGuestsTo(fn (Request $request) => null);
        // A password is used exactly as typed. The framework's default list omits new_password.
        $middleware->trimStrings(except: ['password', 'current_password', 'new_password']);
        $middleware->alias([
            'frontend' => RequireStatefulFrontend::class,
            'json.body' => RequireJsonBody::class,
            'session.current' => EnsureSessionIsCurrent::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );

        $exceptions->dontFlash(['password', 'current_password', 'new_password']);

        $exceptions->render(fn (Throwable $exception, Request $request) => ProblemDetails::fromThrowable($exception, $request));

        // The message of a query exception contains the SQL with its bindings, such as a password
        // hash or an email address. Log only what identifies the failure.
        $exceptions->report(function (QueryException $exception): bool {
            Log::error('Database query failed.', [
                'sqlstate' => $exception->getCode(),
                'connection' => $exception->getConnectionName(),
            ]);

            return false;
        });
    })->create();
