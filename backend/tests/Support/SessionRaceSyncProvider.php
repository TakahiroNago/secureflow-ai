<?php

namespace Tests\Support;

use Illuminate\Support\ServiceProvider;

/**
 * Added to bootstrap/providers.php by scripts/test-session-race.sh for the length of the test, on a
 * throwaway stack only. Nothing else refers to it.
 */
final class SessionRaceSyncProvider extends ServiceProvider
{
    public function boot(): void
    {
        config()->set('sanctum.middleware.validate_csrf_token', SessionRaceSyncPoint::class);
        config()->set('sanctum.middleware.encrypt_cookies', SessionRaceResponseHold::class);
    }
}
