<?php

namespace Tests\Support;

use App\Http\Middleware\ValidateCsrfTokenOfLogin;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * For scripts/test-session-race.sh only, never registered by the application. It takes the place of the
 * CSRF middleware, the first one after the session was read, and holds the request after everything inside
 * it ran and before the session is saved, until the script says to go on, so the race happens every time
 * instead of sometimes. A request without a login is turned away with an exception by that middleware,
 * which is why it wraps it rather than following it.
 */
final class SessionRaceSyncPoint
{
    private const MAX_WAIT_SECONDS = 30;

    public function __construct(private readonly ValidateCsrfTokenOfLogin $csrf) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            return $this->csrf->handle($request, $next);
        } finally {
            self::hold((string) $request->header('X-Test-Session-Sync'));
        }
    }

    public static function hold(string $name): void
    {
        if (preg_match('/^[a-z0-9-]{1,64}$/', $name) !== 1) {
            return;
        }

        $directory = sys_get_temp_dir().'/session-race';
        if (! is_dir($directory)) {
            mkdir($directory, 0700, true);
        }

        touch($directory.'/'.$name.'.reached');

        $deadline = hrtime(true) + self::MAX_WAIT_SECONDS * 1_000_000_000;
        while (! is_file($directory.'/'.$name.'.release') && hrtime(true) < $deadline) {
            usleep(20_000);
        }
    }
}
