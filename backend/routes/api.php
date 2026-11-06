<?php

use App\Http\Controllers\Api\V1\AccountPasswordController;
use App\Http\Controllers\Api\V1\AuthController;
use App\Http\Controllers\HealthController;
use Illuminate\Support\Facades\Route;
use Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful;

/*
| Health checks (no authentication). Rate limiting is applied by nginx, not by the
| application, so that readiness can still answer when Redis is unavailable.
| They skip the session middleware even when a browser calls them: sessions live in Redis, and
| liveness must not depend on it. See docs/api-design.md §3.10.
*/
Route::withoutMiddleware(EnsureFrontendRequestsAreStateful::class)->group(function (): void {
    Route::get('/health/live', [HealthController::class, 'live'])->name('health.live');
    Route::get('/health/ready', [HealthController::class, 'ready'])->name('health.ready');
});

/*
| Every route in this group except login needs a session. A test walks the route list, so a new
| route without authentication fails the suite (ST-05).
*/
Route::prefix('v1')->middleware('json.body')->group(function (): void {
    Route::post('/auth/login', [AuthController::class, 'login'])
        ->middleware(['frontend', 'throttle:login'])
        ->name('auth.login');

    Route::middleware(['db.available', 'auth:sanctum', 'session.current', 'org.context'])->group(function (): void {
        Route::post('/auth/logout', [AuthController::class, 'logout'])->name('auth.logout');
        Route::get('/auth/me', [AuthController::class, 'me'])->name('auth.me');
        Route::patch('/account/password', [AccountPasswordController::class, 'update'])
            ->middleware('throttle:account-password')
            ->name('account.password');
    });
});
