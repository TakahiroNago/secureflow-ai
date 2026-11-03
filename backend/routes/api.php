<?php

use App\Http\Controllers\HealthController;
use Illuminate\Support\Facades\Route;

/*
| Health checks (no authentication). Rate limiting is applied by nginx, not by the
| application, so that readiness can still answer when Redis is unavailable.
| See docs/api-design.md §3.10.
*/
Route::get('/health/live', [HealthController::class, 'live'])->name('health.live');
Route::get('/health/ready', [HealthController::class, 'ready'])->name('health.ready');
