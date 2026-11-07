<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

// In this process, not as a command: the scheduler sends a command's output to /dev/null, and with
// LOG_CHANNEL=stderr that would discard the gauge and the suppressed totals (AUDIT-MON-01).
Schedule::call(fn () => Artisan::call('audit:housekeeping'))->name('audit:housekeeping')->everyMinute();
Schedule::call(fn () => Artisan::call('analysis:recover'))->name('analysis:recover')->everyMinute();
Schedule::call(fn () => Artisan::call('executions:reap-stale'))->name('executions:reap-stale')->everyMinute();
