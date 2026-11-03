<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redis;
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
     * Readiness: the database (application role) and Redis are reachable.
     */
    public function ready(): JsonResponse
    {
        $checks = [
            'database' => static function (): void {
                DB::connection('pgsql')->select('SELECT 1');
            },
            'redis' => static function (): void {
                Redis::connection()->ping();
            },
        ];

        $failed = [];
        foreach ($checks as $name => $check) {
            try {
                $check();
            } catch (Throwable $e) {
                $failed[] = $name;
                // Log the exception class only: messages may contain hostnames or credentials.
                Log::warning('readiness check failed', [
                    'dependency' => $name,
                    'exception' => $e::class,
                ]);
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
