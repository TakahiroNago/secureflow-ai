<?php

namespace App\Domain\Auth;

use App\Models\User;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use Throwable;

/**
 * The server-side state of a login: when it started, and which password it was made with.
 *
 * Only a keyed fingerprint of the password hash is stored, so the hash itself stays out of Redis.
 * Other sessions stop matching as soon as the password changes, which needs nothing from Redis.
 */
final class AuthenticatedSession
{
    private const STARTED_AT = 'auth.started_at';

    private const FINGERPRINT = 'auth.password_fingerprint';

    public function __construct(
        private readonly PendingFingerprintStore $pending,
        private readonly RetiredSessions $retired,
    ) {}

    /**
     * Whether the session holds a login at all, before anything looks it up.
     */
    public static function hasLogin(Request $request): bool
    {
        return $request->hasSession() && $request->session()->has(Auth::guard('web')->getName());
    }

    public function start(Request $request, User $user): void
    {
        $session = $request->session();

        // Before login(): that already replaces the id, and this is about the id the request came with.
        $this->retired->retire($session->getId());

        Auth::guard('web')->login($user);

        $session->regenerate(true);
        $session->regenerateToken();
        $session->put(self::STARTED_AT, now()->getTimestamp());
        $session->put(self::FINGERPRINT, $this->fingerprint($user->getAuthPassword()));
    }

    /**
     * Anything missing counts as not current, so a session without this state is never accepted.
     * A pending fingerprint only helps when it matches the committed hash: before a commit, or after
     * a rollback, it cannot match. When it does match, the session is brought up to date.
     */
    public function isCurrent(Request $request, User $user): bool
    {
        $session = $request->session();

        if (! $user->is_active || ! $this->isWithinAbsoluteLifetime($session)) {
            return false;
        }

        $current = $this->fingerprint($user->getAuthPassword());

        if (hash_equals($current, (string) $session->get(self::FINGERPRINT))) {
            return true;
        }

        $pending = $this->pending->read($session->getId());

        if ($pending === null || ! hash_equals($current, $pending)) {
            return false;
        }

        return $this->finishPasswordChange($request, $user->getAuthPassword());
    }

    /**
     * Writes the new id first and removes the old one after, so a failure in between leaves a working
     * session. A cookie for an id that was not stored is never sent: the id goes back on failure.
     *
     * Only one request rotates a session. False means another one has it or is about to: this request
     * no longer speaks for the session, and StartSessionUnlessRetired keeps it from writing the old id.
     *
     * @throws ServiceUnavailableException the session could not be saved. The database is not touched.
     */
    public function finishPasswordChange(Request $request, string $passwordHash, ?string $owner = null): bool
    {
        $session = $request->session();
        $fingerprint = $this->fingerprint($passwordHash);

        if (hash_equals($fingerprint, (string) $session->get(self::FINGERPRINT))) {
            return true;
        }

        $oldId = $session->getId();

        if (! $this->pending->mayRotate($oldId, $owner) || ! $this->retired->claim($oldId)) {
            return false;
        }

        $oldFingerprint = $session->get(self::FINGERPRINT);

        try {
            $session->migrate(false);
            $session->put(self::FINGERPRINT, $fingerprint);
            $session->save();
        } catch (Throwable $exception) {
            $session->setId($oldId);
            $session->put(self::FINGERPRINT, $oldFingerprint);
            $this->undoRetirement($oldId);

            throw new ServiceUnavailableException('The session could not be saved.', 0, $exception);
        }

        $this->removeOldSession($session, $oldId);

        return true;
    }

    /**
     * True when a parallel request ended or replaced this session: ending it here would only create
     * another session and another cookie.
     */
    public function wasRetired(Request $request): bool
    {
        return $this->retired->isRetired($request->session()->getId());
    }

    /**
     * True for the session that made this change, by its pending fingerprint, and for a session
     * started with the new password. A session from before the change is neither, even when it
     * sent the same key and content at the same moment.
     */
    public function holdsPassword(Request $request, string $passwordHash): bool
    {
        $session = $request->session();
        $fingerprint = $this->fingerprint($passwordHash);

        if (hash_equals($fingerprint, (string) $session->get(self::FINGERPRINT))) {
            return true;
        }

        $pending = $this->pending->read($session->getId());

        return $pending !== null && hash_equals($fingerprint, $pending);
    }

    public function pendingFingerprint(string $passwordHash): string
    {
        return $this->fingerprint($passwordHash);
    }

    public function end(Request $request): void
    {
        $session = $request->session();

        // A parallel request got here first, and the browser has the cookie from that one.
        if (! $this->retired->claim($session->getId())) {
            Auth::guard('web')->logout();

            return;
        }

        Auth::guard('web')->logout();

        $session->invalidate();
        $session->regenerateToken();
    }

    /**
     * If Redis is what failed this cannot work either. The claim then stands and the session gets 401,
     * which needs a new login but leaves nothing inconsistent.
     */
    private function undoRetirement(string $sessionId): void
    {
        try {
            $this->retired->restore($sessionId);
            $this->pending->giveUpOwnership($sessionId);
        } catch (Throwable) {
            logger()->critical('auth.session_rotation_not_released', ['metric' => 'auth.session_rotation_not_released']);
        }
    }

    private function removeOldSession(Session $session, string $oldId): void
    {
        try {
            if ($session instanceof Store) {
                $session->getHandler()->destroy($oldId);
            }
        } catch (Throwable) {
            // The old id expires at the idle limit, and a user could not reach this without its cookie.
            logger()->critical('auth.old_session_not_removed', ['metric' => 'auth.old_session_not_removed']);
        }
    }

    private function isWithinAbsoluteLifetime(Session $session): bool
    {
        $startedAt = $session->get(self::STARTED_AT);

        if (! is_int($startedAt)) {
            return false;
        }

        return now()->getTimestamp() - $startedAt < config()->integer('session.absolute_hours') * 3600;
    }

    private function fingerprint(string $passwordHash): string
    {
        return hash_hmac('sha256', $passwordHash, config()->string('app.key'));
    }
}
