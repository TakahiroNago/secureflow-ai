<?php

namespace App\Http\Controllers;

use App\Audit\AuditAvailability;
use App\Audit\OutageLog;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Redis;
use RuntimeException;
use Throwable;

/**
 * Liveness / Readiness endpoints.
 *
 * Responses intentionally contain only {"status": ...}: no version, host, dependency
 * names or error details are returned to the client (docs/architecture.md §4.2).
 * Failure details are written to the application log only.
 */
class HealthController extends Controller
{
    /**
     * Liveness: the PHP process can serve a request. External dependencies are not checked.
     */
    public function live(): JsonResponse
    {
        return $this->respond('ok', 200);
    }

    /**
     * Readiness: the database (application role) and Redis are reachable. It may be polled every few
     * seconds, so failures are logged as started, continuing and recovered with counts, not per request.
     */
    public function ready(OutageLog $log): JsonResponse
    {
        $checks = [
            'database' => static function (): void {
                DB::connection('pgsql')->select('SELECT 1');
            },
            'redis' => static function (): void {
                Redis::connection()->ping();
            },
            // A storage failure may affect the whole database, so this is not "ready". Liveness and
            // the container healthchecks do not use this: a restart would not free any disk.
            'storage' => static function (): void {
                if (app(AuditAvailability::class)->storageSuspected()) {
                    throw new RuntimeException('Storage failure suspected.');
                }
            },
        ];

        $failed = [];
        foreach ($checks as $name => $check) {
            // The storage state lives in Redis: a Redis failure is one failure, not two.
            if ($name === 'storage' && in_array('redis', $failed, true)) {
                continue;
            }

            try {
                $check();
                $log->recovered('readiness.'.$name);
            } catch (Throwable $e) {
                $failed[] = $name;
                // The exception class only: messages may contain hostnames or credentials.
                $log->failure('readiness.'.$name, class_basename($e), ['dependency' => $name, 'exception' => $e::class]);
            }
        }

        return $failed === []
            ? $this->respond('ok', 200)
            : $this->respond('unavailable', 503);
    }

    private function respond(string $status, int $code): JsonResponse
    {
        return response()
            ->json(['status' => $status], $code)
            ->header('Cache-Control', 'no-store');
    }
}
