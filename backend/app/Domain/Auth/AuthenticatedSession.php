<?php

namespace App\Domain\Auth;

use App\Models\User;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * The server-side state of a login: when it started, and which password it was made with.
 *
 * Only a keyed fingerprint of the password hash is stored, so the hash itself stays out of Redis.
 * Other sessions stop matching as soon as the password changes.
 */
final class AuthenticatedSession
{
    private const STARTED_AT = 'auth.started_at';

    private const FINGERPRINT = 'auth.password_fingerprint';

    public function start(Request $request, User $user): void
    {
        Auth::guard('web')->login($user);

        $session = $request->session();
        $session->regenerate(true);
        $session->regenerateToken();
        $session->put(self::STARTED_AT, now()->getTimestamp());
        $session->put(self::FINGERPRINT, $this->fingerprint($user));
    }

    /**
     * Anything missing counts as not current, so a session without this state is never accepted.
     */
    public function isCurrent(Request $request, User $user): bool
    {
        $session = $request->session();

        return $user->is_active
            && $this->isWithinAbsoluteLifetime($session)
            && hash_equals($this->fingerprint($user), (string) $session->get(self::FINGERPRINT));
    }

    /**
     * After a password change: this session stays valid, every other one stops matching.
     * The start time is kept, so changing a password does not extend the absolute limit.
     */
    public function keepAfterPasswordChange(Request $request, User $user): void
    {
        $session = $request->session();
        $session->regenerate(true);
        $session->put(self::FINGERPRINT, $this->fingerprint($user));
    }

    public function end(Request $request): void
    {
        Auth::guard('web')->logout();

        $session = $request->session();
        $session->invalidate();
        $session->regenerateToken();
    }

    private function isWithinAbsoluteLifetime(Session $session): bool
    {
        $startedAt = $session->get(self::STARTED_AT);

        if (! is_int($startedAt)) {
            return false;
        }

        return now()->getTimestamp() - $startedAt < config()->integer('session.absolute_hours') * 3600;
    }

    private function fingerprint(User $user): string
    {
        return hash_hmac('sha256', $user->getAuthPassword(), config()->string('app.key'));
    }
}
