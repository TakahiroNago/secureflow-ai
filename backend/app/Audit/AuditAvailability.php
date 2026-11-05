<?php

namespace App\Audit;

use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use PDOException;
use Ramsey\Uuid\Uuid;
use Throwable;

/**
 * DB unavailable and Audit unavailable, kept apart (docs/security-design.md §16.5.1).
 *
 * DB unavailable comes only from a new connection failing with 08006. A lost connection alone is not
 * enough: pg_terminate_backend and idle timeouts lose one connection and the probe succeeds.
 * Audit unavailable comes only from audit_append() failing with a storage or configuration error.
 * Lock waits and timeouts fail that one operation and change no state. Message text decides nothing.
 */
class AuditAvailability
{
    public const READ_CONNECTION = 'pgsql_audit_read';

    public const SCOPE_DB_SUSPECTED = 'db_suspected';

    public const SCOPE_AUDIT_ONLY = 'audit_only';

    public const RECOVERY_NAMESPACE = '5d8c6f2e-4b1a-5e7c-9a3d-2f6b8c1e4d70';

    private const DB_KEY = 'audit:db_unavailable';

    private const AUDIT_KEY = 'audit:unavailable';

    private const RECOVERY_LOCK_KEY = 'audit:recovery_check';

    private const RECOVERY_LOCK_SECONDS = 10;

    /** Outlives the flag: its expiry must lead to one recheck, not to every request connecting. */
    private const DB_SUSPECT_KEY = 'audit:db_suspect';

    private const DB_SUSPECT_SECONDS = 86400;

    private const DB_RECHECK_LOCK_KEY = 'audit:db_recheck';

    /** Longer than a connection attempt can take. A crash leaves the next request waiting this long at most. */
    private const DB_RECHECK_LOCK_SECONDS = 15;

    public function __construct(
        private readonly AuditWriter $writer,
        private readonly OutageLog $log,
    ) {}

    /**
     * Runs before any user lookup or password check, and is the same for every request, so its
     * result says nothing about an account.
     *
     * @throws ServiceUnavailableException
     */
    public function assertAvailable(): void
    {
        $this->assertDatabaseUsable();

        $state = $this->auditState();

        if ($state !== null && ! $this->recoveredNow($state)) {
            $this->log->failure('audit', $state['failure_class'], ['outage_id' => $state['outage_id']]);

            throw new ServiceUnavailableException('The audit log cannot be written.');
        }

        $this->checkDatabase();
    }

    /**
     * No connection while the flag is up. Once it expires, one request connects and the others get
     * 503 at once, so a recheck costs one slow request however many are waiting.
     *
     * @throws ServiceUnavailableException
     */
    public function assertDatabaseUsable(): void
    {
        $flagged = $this->dbFlagged();
        $this->log->recovered('redis');

        if ($flagged) {
            $this->reject('db', 'flag');
        }

        if (Cache::get(self::DB_SUSPECT_KEY) === null) {
            return;
        }

        if (! Cache::add(self::DB_RECHECK_LOCK_KEY, true, self::DB_RECHECK_LOCK_SECONDS)) {
            $this->reject('db', 'recheck_in_progress');
        }

        try {
            $failure = $this->connectAnew();

            if ($failure !== null) {
                $this->reject('db', $failure->cause, $failure->sqlState);
            }

            $this->log->recovered('db');
        } finally {
            Cache::forget(self::DB_RECHECK_LOCK_KEY);
        }
    }

    public function reportWriteFailure(Throwable $exception, AuditEntry $entry, string $outcome, ?string $requestId = null): void
    {
        $failure = AuditFailure::from($exception);

        try {
            $this->log->occurrence('audit.write_failed', 'audit.write_failed.'.$failure->class.'.'.$entry->type->value, [
                'event_type' => $entry->type->value,
                'outcome' => $outcome,
                'failure_class' => $failure->class,
                'chain' => $entry->chainKind(),
                'sqlstate' => $failure->sqlState,
                'cause' => $failure->cause,
                'exception' => $exception::class,
                'request_id' => $requestId,
            ]);

            if ($failure->isConnection()) {
                $this->probe();
            } elseif ($failure->makesAuditUnavailable()) {
                $this->markAuditUnavailable($failure);
            }
        } catch (Throwable $secondary) {
            // Reporting must never change the response of the request it reports on.
            Log::critical('audit.state_update_failed', ['metric' => 'audit.state_update_failed', 'exception' => $secondary::class]);
        }
    }

    /**
     * A new connection, one try, no reuse. Only 08006 from here means DB unavailable.
     */
    public function probe(): void
    {
        if (! $this->probeAllowed()) {
            return;
        }

        $this->connectAnew();
    }

    /**
     * Only 08006 on a new connection sets the flag. Success clears the suspicion.
     */
    private function connectAnew(): ?AuditFailure
    {
        try {
            DB::purge(self::READ_CONNECTION);
            DB::connection(self::READ_CONNECTION)->select('SELECT 1');
            DB::purge(self::READ_CONNECTION);
            Cache::forget(self::DB_SUSPECT_KEY);

            return null;
        } catch (QueryException|PDOException $exception) {
            $failure = AuditFailure::from($exception);
            DB::purge(self::READ_CONNECTION);

            if ($failure->sqlState === '08006') {
                Cache::put(self::DB_KEY, true, config()->integer('audit.db_unavailable_ttl_seconds'));
                Cache::put(self::DB_SUSPECT_KEY, true, self::DB_SUSPECT_SECONDS);
                $this->log->failure('db', $failure->cause, ['sqlstate' => $failure->sqlState]);
            }

            return $failure;
        }
    }

    /**
     * True while a storage failure may affect the whole database: readiness answers 503.
     */
    public function storageSuspected(): bool
    {
        return ($this->auditState()['storage_scope'] ?? null) === self::SCOPE_DB_SUSPECTED;
    }

    /**
     * @return array{outage_id: string, failure_class: string, storage_scope: ?string, started_at: int, next_check_at: int}|null
     */
    public function auditState(): ?array
    {
        $state = Cache::get(self::AUDIT_KEY);

        return is_array($state) ? $state : null; // @phpstan-ignore return.type
    }

    public function dbFlagged(): bool
    {
        return Cache::get(self::DB_KEY) !== null;
    }

    private function markAuditUnavailable(AuditFailure $failure): void
    {
        $now = now()->getTimestamp();
        $scope = $failure->class === AuditFailure::STORAGE ? self::SCOPE_DB_SUSPECTED : null;
        $outageId = (string) Str::uuid7();

        // add: the first failure of an outage owns the outage id.
        Cache::add(self::AUDIT_KEY, [
            'outage_id' => $outageId,
            'failure_class' => $failure->class,
            'storage_scope' => $scope,
            'started_at' => $now,
            'next_check_at' => $now + config()->integer('audit.recheck_interval_seconds'),
        ], 86400 * 30);

        $this->log->failure('audit', $failure->class, [
            'failure_class' => $failure->class,
            'storage_scope' => $scope,
            'storage_area' => $failure->storageArea,
            'outage_id' => $this->auditState()['outage_id'] ?? $outageId,
            'sqlstate' => $failure->sqlState,
        ]);
    }

    /**
     * @param  array{outage_id: string, failure_class: string, storage_scope: ?string, started_at: int, next_check_at: int}  $state
     */
    private function recoveredNow(array $state): bool
    {
        $now = now()->getTimestamp();

        if ($now < $state['next_check_at'] || ! Cache::add(self::RECOVERY_LOCK_KEY, true, self::RECOVERY_LOCK_SECONDS)) {
            return false;
        }

        try {
            if (! $this->recordRecovery($state)) {
                $state['next_check_at'] = $now + config()->integer('audit.recheck_interval_seconds');
                Cache::put(self::AUDIT_KEY, $state, 86400 * 30);

                return false;
            }

            Cache::forget(self::AUDIT_KEY);
            $this->log->recovered('audit', [
                'outage_id' => $state['outage_id'],
                'recovery_scope' => 'audit_path',
            ]);

            return true;
        } finally {
            Cache::forget(self::RECOVERY_LOCK_KEY);
        }
    }

    /**
     * A real append, because a read cannot prove that writing works again. The event id comes from
     * the outage id, so the unique constraint allows one row per outage id. A failure records nothing.
     *
     * @param  array{outage_id: string}  $state
     */
    private function recordRecovery(array $state): bool
    {
        $eventId = Uuid::uuid5(self::RECOVERY_NAMESPACE, $state['outage_id'])->toString();
        $entry = AuditEntry::system(AuditEventType::AvailabilityChecked, metadata: ['outage_id' => $state['outage_id']], eventId: $eventId);

        try {
            SingleAttemptTransaction::run(DB::connection(AuditWriter::CONNECTION), fn () => $this->writer->append($entry, null, null));

            return true;
        } catch (Throwable $exception) {
            if (AuditFailure::from($exception)->sqlState === 'SF001') {
                return $this->alreadyRecorded($eventId, $state['outage_id']);
            }

            return false;
        }
    }

    /**
     * SF001 alone proves nothing: it could be raised by anything on this connection. Check the row.
     */
    private function alreadyRecorded(string $eventId, string $outageId): bool
    {
        $current = $this->auditState();
        $row = DB::connection(AuditWriter::CONNECTION)->selectOne(
            "SELECT event_type, chain_id, metadata ->> 'outage_id' AS outage_id FROM audit_logs WHERE event_id = ?::uuid",
            [$eventId],
        );

        if (($current['outage_id'] ?? null) === $outageId
            && $row !== null
            && $row->event_type === AuditEventType::AvailabilityChecked->value
            && $row->chain_id === AuditCanonicalizer::SYSTEM_CHAIN
            && $row->outage_id === $outageId) {
            return true;
        }

        Log::critical('audit.recovery_check_conflict', ['metric' => 'audit.recovery_check_conflict', 'outage_id' => $outageId]);

        return false;
    }

    private function checkDatabase(): void
    {
        try {
            $row = SingleAttemptTransaction::run(DB::connection(AuditWriter::CONNECTION), function ($db) {
                $db->select("SELECT set_config('statement_timeout', ?, true)", [(string) config()->integer('audit.preflight_timeout_ms')]);

                return $db->selectOne(
                    "SELECT has_function_privilege(current_user, 'public.audit_append(uuid, uuid, text, uuid, text, text, uuid, text, text, inet, uuid, jsonb)', 'EXECUTE') AS can_append,
                            current_setting('transaction_read_only') = 'off' AS writable,
                            NOT pg_is_in_recovery() AS primary_server"
                );
            });
        } catch (QueryException|PDOException $exception) {
            $failure = AuditFailure::from($exception);

            if ($failure->isConnection()) {
                $this->probe();
            }

            $this->reject('db', $failure->cause, $failure->sqlState);
        }

        if (! $row->can_append || ! $row->writable || ! $row->primary_server) {
            $this->log->occurrence('audit.preflight_failed', 'audit.preflight_failed', [
                'failure_class' => AuditFailure::PERMANENT_CONFIG,
                'can_append' => $row->can_append ? 1 : 0,
                'writable' => $row->writable ? 1 : 0,
                'primary_server' => $row->primary_server ? 1 : 0,
            ]);

            throw new ServiceUnavailableException('The audit log cannot be written.');
        }

        $this->log->recovered('db');
    }

    private function reject(string $subject, string $cause, ?string $sqlState = null): never
    {
        $this->log->failure($subject, $cause, ['sqlstate' => $sqlState]);

        throw new ServiceUnavailableException('The database cannot be used.');
    }

    /**
     * At most one probe per interval in this container, so a run of failures cannot open a
     * connection per request. The local file only limits frequency and decides nothing else.
     */
    private function probeAllowed(): bool
    {
        $directory = $this->log->directory();
        if (! is_dir($directory)) {
            @mkdir($directory, 0700, true);
        }

        $file = $directory.'/probe';
        $interval = config()->integer('audit.probe_min_interval_seconds');
        $last = (int) @file_get_contents($file);

        if ($last > 0 && now()->getTimestamp() - $last < $interval) {
            return false;
        }

        @file_put_contents($file, (string) now()->getTimestamp());

        return true;
    }
}
