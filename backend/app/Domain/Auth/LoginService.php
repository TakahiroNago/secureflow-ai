<?php

namespace App\Domain\Auth;

use App\Events\AccountLocked;
use App\Models\User;
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use SensitiveParameter;

/**
 * Decides whether credentials may start a session (docs/security-design.md §12).
 *
 * The result is only ever a user or null, and a password hash is always verified, so an unknown
 * address, a wrong password, a disabled account and a locked account look the same from outside.
 */
final class LoginService
{
    public const MAX_FAILURES = 5;

    public const LOCK_MINUTES = 15;

    public function attempt(string $email, #[SensitiveParameter] string $password): ?User
    {
        $user = User::query()->where('email', $email)->first();

        $passwordMatches = Hash::check($password, $user === null ? $this->dummyHash() : $user->getAuthPassword());

        if ($user === null || $user->isLocked() || ! $user->is_active) {
            return $this->failed($user, $email);
        }

        if (! $passwordMatches) {
            $this->recordFailure($user);

            return $this->failed($user, $email);
        }

        $user->forceFill([
            'failed_login_count' => 0,
            'locked_until' => null,
            'last_login_at' => now(),
        ])->save();

        return $user;
    }

    /**
     * A single statement, so concurrent failures cannot overwrite each other's count. The row is
     * left alone while locked: more attempts neither extend the lock nor count towards the next.
     */
    public function recordFailure(User $user): void
    {
        $now = now();

        $row = DB::selectOne(
            'UPDATE users
             SET failed_login_count = CASE WHEN failed_login_count + 1 >= ? THEN 0 ELSE failed_login_count + 1 END,
                 locked_until = CASE WHEN failed_login_count + 1 >= ? THEN ?::timestamptz ELSE NULL END,
                 updated_at = ?::timestamptz
             WHERE id = ? AND (locked_until IS NULL OR locked_until <= ?::timestamptz)
             RETURNING locked_until',
            [
                self::MAX_FAILURES,
                self::MAX_FAILURES,
                $now->copy()->addMinutes(self::LOCK_MINUTES)->toIso8601String(),
                $now->toIso8601String(),
                $user->id,
                $now->toIso8601String(),
            ],
        );

        if ($row !== null && $row->locked_until !== null) {
            AccountLocked::dispatch($user);
        }
    }

    private function failed(?User $user, string $email): null
    {
        // Observers get the address only, never the password (audit recording is step 1-3).
        event(new Failed('web', $user, ['email' => $email]));

        return null;
    }

    /**
     * Verified when the address is unknown, so that case costs the same as a real one. Generated
     * rather than stored in the repository, and keyed by the parameters so that a cost change
     * takes effect at once.
     */
    private function dummyHash(): string
    {
        $key = 'auth:dummy-hash:'.md5(serialize(config('hashing.argon')));

        return Cache::rememberForever($key, fn (): string => Hash::make(Str::random(64)));
    }
}
