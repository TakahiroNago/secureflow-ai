<?php

use App\Audit\AuditAvailability;
use App\Audit\AuditFailure;
use App\Audit\OutageLog;
use App\Audit\RefusalRecorder;
use App\Domain\Execution\IdempotencyKeyReusedException;
use App\Domain\Workflow\AiLimitExceededException;
use App\Domain\Workflow\RiskAcknowledgementRequiredException;
use App\Domain\Workflow\WorkflowConflictException;
use App\Http\Middleware\EnsureSessionIsCurrent;
use App\Http\Middleware\NoStoreResponses;
use App\Http\Middleware\RecordDeniedAttempt;
use App\Http\Middleware\RejectWhileDatabaseUnavailable;
use App\Http\Middleware\RequireJsonBody;
use App\Http\Middleware\RequireStatefulFrontend;
use App\Http\Middleware\SetOrganizationContext;
use App\Http\Middleware\ThrottleUnauthenticated;
use App\Support\Http\PreconditionRequiredException;
use App\Support\Http\ProblemDetails;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
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
        // Before Sanctum's stack, which already turns away a request with no session: the limit for guests is outside it.
        $middleware->api(prepend: [ThrottleUnauthenticated::class]);
        $middleware->statefulApi();
        $middleware->prepend(NoStoreResponses::class);
        // An API with no login page: answer 401 whatever the client accepts.
        $middleware->redirectGuestsTo(fn (Request $request) => null);
        // A password is used exactly as typed. The framework's default list omits new_password.
        $middleware->trimStrings(except: ['password', 'current_password', 'new_password']);
        $middleware->alias([
            'frontend' => RequireStatefulFrontend::class,
            'db.available' => RejectWhileDatabaseUnavailable::class,
            'json.body' => RequireJsonBody::class,
            'session.current' => EnsureSessionIsCurrent::class,
            'org.context' => SetOrganizationContext::class,
            'denied.attempt' => RecordDeniedAttempt::class,
        ]);
        // Without this the framework moves authentication first, and it reads the users table.
        $middleware->prependToPriorityList(AuthenticatesRequests::class, RejectWhileDatabaseUnavailable::class);
        // Route model binding must run inside the organization scope.
        $middleware->appendToPriorityList(AuthenticatesRequests::class, SetOrganizationContext::class);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );

        $exceptions->dontFlash(['password', 'current_password', 'new_password', 'input']);

        $exceptions->render(function (Throwable $exception, Request $request) {
            app(RefusalRecorder::class)->note($exception, $request);

            return ProblemDetails::fromThrowable($exception, $request);
        });

        // The message of a query exception contains the SQL with its bindings, such as a password
        // hash or an email address. Log only what identifies the failure.
        // PDOException too: a failed connect while opening a transaction arrives unwrapped.
        $exceptions->report(function (PDOException $exception): bool {
            $failure = AuditFailure::from($exception);

            Log::error('Database query failed.', [
                'metric' => 'db.query_failed',
                'sqlstate' => $failure->sqlState,
                'cause' => $failure->cause,
                'connection' => $exception instanceof QueryException ? $exception->getConnectionName() : null,
            ]);

            // Not a state change: only audit_append() decides that. It may still be the same disk.
            if ($failure->class === AuditFailure::STORAGE) {
                app(OutageLog::class)->occurrence('db.storage_error', 'db.storage_error.'.$failure->storageArea, [
                    'sqlstate' => $failure->sqlState,
                    'storage_area' => $failure->storageArea,
                ]);
            }

            // Any route can be the first to notice, not only the ones with a preflight.
            if ($failure->isConnection()) {
                try {
                    app(AuditAvailability::class)->probe();
                } catch (Throwable) {
                    // Redis may be down too. Reporting must not change the response.
                }
            }

            return false;
        });

        // During an outage this would otherwise be one line per request.
        $exceptions->report(function (RedisException $exception): bool {
            app(OutageLog::class)->failure('redis', match (true) {
                str_contains($exception->getMessage(), 'Connection refused') => 'connection_refused',
                str_contains($exception->getMessage(), 'getaddrinfo') => 'name_resolution',
                str_contains($exception->getMessage(), 'read error') => 'read_timeout',
                str_contains($exception->getMessage(), 'WRONGPASS'), str_contains($exception->getMessage(), 'NOAUTH') => 'auth_failed',
                default => 'unknown',
            });

            return false;
        });

        // Already logged by whatever raised it, and part of normal operation during an outage.
        $exceptions->dontReport(ServiceUnavailableException::class);
        $exceptions->dontReport(WorkflowConflictException::class);
        $exceptions->dontReport(RiskAcknowledgementRequiredException::class);
        $exceptions->dontReport(IdempotencyKeyReusedException::class);
        $exceptions->dontReport(AiLimitExceededException::class);
        $exceptions->dontReport(PreconditionRequiredException::class);
    })->create();
