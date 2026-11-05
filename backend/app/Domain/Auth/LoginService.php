<?php

namespace App\Domain\Auth;

use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Events\AccountLocked;
use App\Models\User;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use SensitiveParameter;

/**
 * Decides whether credentials may start a session (docs/security-design.md §12, §16.5.1).
 *
 * A password hash is always verified, so an unknown address, a wrong password, a disabled account
 * and a locked account look the same from outside. If a required audit record cannot be written the
 * answer is 503 whether or not the credentials were right, so the response cannot reveal them.
 */
final class LoginService
{
    public const MAX_FAILURES = 5;

    public const LOCK_MINUTES = 15;

    public function __construct(
        private readonly AuditLogger $audit,
        private readonly AuditAvailability $availability,
    ) {}

    /**
     * @throws ServiceUnavailableException
     */
    public function attempt(string $email, #[SensitiveParameter] string $password): ?User
    {
        $this->availability->assertAvailable();

        $user = User::query()->where('email', $email)->first();

        $passwordMatches = Hash::check($password, $user === null ? $this->dummyHash() : $user->getAuthPassword());

        if ($user === null) {
            return $this->failed(null, $email, 'UNKNOWN_ACCOUNT');
        }

        if ($user->isLocked()) {
            return $this->failed($user, $email, 'ACCOUNT_LOCKED');
        }

        if (! $user->is_active) {
            return $this->failed($user, $email, 'ACCOUNT_INACTIVE');
        }

        if (! $passwordMatches) {
            $locked = $this->recordFailure($user);
            $this->failed($user, $email, 'INVALID_PASSWORD');

            if ($locked && ! $this->audit->recordAfterTransaction(AuditEntry::system(AuditEventType::Locked, $user, 'denied'), 'locked_unrecorded')) {
                throw new ServiceUnavailableException('A required audit record could not be written.');
            }

            return null;
        }

        // The session starts only after this commits. A failed record undoes the login state with it.
        SingleAttemptTransaction::run(DB::connection(), function () use ($user): void {
            $user->forceFill([
                'failed_login_count' => 0,
                'locked_until' => null,
                'last_login_at' => now(),
            ])->save();

            $this->audit->recordInTransaction(AuditEntry::byUser(AuditEventType::Login, $user), 'login_denied');
        });

        return $user;
    }

    /**
     * A single statement, so concurrent failures cannot overwrite each other's count. The row is
     * left alone while locked: more attempts neither extend the lock nor count towards the next.
     *
     * @return bool whether this failure locked the account
     */
    public function recordFailure(User $user): bool
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

            return true;
        }

        return false;
    }

    /**
     * @throws ServiceUnavailableException when the failure cannot be recorded
     */
    private function failed(?User $user, string $email, string $reason): null
    {
        // Observers get the address only, never the password. The audit log gets neither: an unknown
        // address is not recorded at all, because people type passwords into that field.
        event(new Failed('web', $user, ['email' => $email]));

        $entry = AuditEntry::anonymous(AuditEventType::LoginFailed, $user, 'failure', ['reason_code' => $reason]);

        if (! $this->audit->recordAfterTransaction($entry, 'login_failed_unrecorded')) {
            throw new ServiceUnavailableException('A required audit record could not be written.');
        }

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
