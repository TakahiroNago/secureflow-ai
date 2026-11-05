<?php

namespace App\Domain\Auth;

use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditFailure;
use App\Audit\AuditLogger;
use App\Models\User;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use SensitiveParameter;
use stdClass;
use Throwable;

/**
 * docs/security-design.md §16.5.5. The commit is the only point of truth: Redis never decides
 * whether a change happened, and a retry is judged from the users row alone.
 */
final class PasswordChangeService
{
    public function __construct(
        private readonly AuditAvailability $availability,
        private readonly AuditLogger $audit,
        private readonly PendingFingerprintStore $pending,
        private readonly AuthenticatedSession $session,
    ) {}

    /**
     * @throws ServiceUnavailableException
     */
    public function change(User $user, string $idempotencyKey, string $sessionId, string $owner, #[SensitiveParameter] string $current, #[SensitiveParameter] string $new): PasswordChangeResult
    {
        $this->availability->assertAvailable();

        $keyHash = $this->keyHash($user, $idempotencyKey);
        $row = $this->row($user);

        if ($this->keyMatches($row, $keyHash)) {
            return $this->replay($row, $current, $new);
        }

        if (! Hash::check($current, $row->password)) {
            return $this->currentInvalid($user);
        }

        if (Hash::check($new, $row->password)) {
            return PasswordChangeResult::of(PasswordChangeResult::SAME_AS_CURRENT);
        }

        $readHash = (string) $row->password;
        $newHash = Hash::make($new);

        $this->pending->prepare();

        try {
            $changedAt = SingleAttemptTransaction::run(DB::connection(), fn () => $this->commit($user, $sessionId, $owner, $readHash, $newHash, $keyHash));
        } catch (ServiceUnavailableException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            return $this->afterDatabaseError($exception, $user, $keyHash, $newHash);
        }

        if ($changedAt === null) {
            return $this->changedElsewhere($user, $keyHash, $current, $new);
        }

        return PasswordChangeResult::changed($changedAt, $newHash);
    }

    /**
     * Holds the user's row lock across one Redis write. The audit head lock comes after it, so no
     * head lock is ever held while talking to Redis. Null means another request committed first.
     */
    private function commit(User $user, string $sessionId, string $owner, string $readHash, string $newHash, string $keyHash): ?string
    {
        $locked = DB::selectOne('SELECT password FROM users WHERE id = ? FOR UPDATE', [$user->id]);

        if ($locked === null || $locked->password !== $readHash) {
            return null;
        }

        $this->pending->write($sessionId, $this->session->pendingFingerprint($newHash), $owner);

        $updated = DB::selectOne(
            'UPDATE users
             SET password = ?, password_changed_at = clock_timestamp(), updated_at = clock_timestamp(),
                 password_change_key_hash = ?, password_change_previous_hash = ?
             WHERE id = ? AND password = ?
             RETURNING password_changed_at',
            [$newHash, $keyHash, $readHash, $user->id, $readHash],
        );

        if ($updated === null) {
            return null;
        }

        $this->audit->recordInTransaction(AuditEntry::byUser(AuditEventType::PasswordChanged, $user), 'password_change_rolled_back');

        return (string) $updated->password_changed_at;
    }

    /**
     * Same key: every one of the four conditions must hold, or the change is not treated as done.
     */
    private function replay(stdClass $row, #[SensitiveParameter] string $current, #[SensitiveParameter] string $new): PasswordChangeResult
    {
        if (Hash::check($new, (string) $row->password)
            && is_string($row->password_change_previous_hash)
            && Hash::check($current, $row->password_change_previous_hash)) {
            return PasswordChangeResult::replayed((string) $row->password_changed_at, (string) $row->password);
        }

        return PasswordChangeResult::of(PasswordChangeResult::KEY_CONFLICT);
    }

    private function changedElsewhere(User $user, string $keyHash, #[SensitiveParameter] string $current, #[SensitiveParameter] string $new): PasswordChangeResult
    {
        $row = $this->row($user);

        if ($this->keyMatches($row, $keyHash)) {
            return $this->replay($row, $current, $new);
        }

        return $this->currentInvalid($user);
    }

    /**
     * The commit may have been lost or may have happened. Ask the database again on a new connection:
     * the key is written in the same transaction, so finding it proves the commit.
     */
    private function afterDatabaseError(Throwable $exception, User $user, string $keyHash, string $newHash): PasswordChangeResult
    {
        if (AuditFailure::from($exception)->isConnection()) {
            try {
                DB::purge(AuditAvailability::READ_CONNECTION);
                $row = DB::connection(AuditAvailability::READ_CONNECTION)->selectOne(
                    'SELECT password, password_change_key_hash, password_changed_at FROM users WHERE id = ?',
                    [$user->id],
                );

                if ($row !== null && $row->password === $newHash && hash_equals((string) $row->password_change_key_hash, $keyHash)) {
                    return PasswordChangeResult::changed((string) $row->password_changed_at, $newHash);
                }
            } catch (Throwable) {
                // Unknown either way: the same key can be retried.
            }
        }

        throw new ServiceUnavailableException('The password change could not be confirmed.', 0, $exception);
    }

    private function currentInvalid(User $user): PasswordChangeResult
    {
        $entry = AuditEntry::byUser(AuditEventType::PasswordChangeFailed, $user, 'failure', ['reason_code' => 'CURRENT_PASSWORD_INVALID']);

        // Without this record, a wrong password would always get 422 and only a right one could get 503.
        if (! $this->audit->recordAfterTransaction($entry, 'password_change_failed_unrecorded')) {
            throw new ServiceUnavailableException('A required audit record could not be written.');
        }

        return PasswordChangeResult::of(PasswordChangeResult::CURRENT_INVALID);
    }

    private function row(User $user): stdClass
    {
        // The expiry is decided here, with the database's clock. The scheduler only tidies up.
        /** @var stdClass */
        return DB::selectOne(
            'SELECT password, password_change_key_hash, password_change_previous_hash, password_changed_at,
                    COALESCE(password_changed_at > clock_timestamp() - make_interval(mins => ?), false) AS replay_open
             FROM users WHERE id = ?',
            [config()->integer('audit.password_change_replay_minutes'), $user->id],
        );
    }

    private function keyMatches(stdClass $row, string $keyHash): bool
    {
        return $row->replay_open
            && is_string($row->password_change_key_hash)
            && hash_equals($row->password_change_key_hash, $keyHash);
    }

    /**
     * Never stored or logged in clear. A key derived for this purpose only: rotating APP_KEY makes old
     * keys unrecognized, so they fall through to normal processing and nothing runs twice.
     */
    private function keyHash(User $user, string $idempotencyKey): string
    {
        $secret = hash_hkdf('sha256', config()->string('app.key'), 32, 'password-change-idempotency');

        return hash_hmac('sha256', 'password-change-idempotency|'.$user->id.'|'.$idempotencyKey, $secret);
    }
}
