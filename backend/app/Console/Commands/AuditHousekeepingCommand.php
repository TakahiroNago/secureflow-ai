<?php

namespace App\Console\Commands;

use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditWriter;
use App\Audit\SystemChainLimiter;
use App\Support\Database\SingleAttemptTransaction;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Ramsey\Uuid\Uuid;
use Throwable;

/**
 * Runs every minute on the scheduler. Each part is independent: one failing must not stop the others.
 */
final class AuditHousekeepingCommand extends Command
{
    private const SUPPRESSED_NAMESPACE = '8a1f3c7e-2d4b-5f60-8b19-7c3e5a9d1f42';

    protected $signature = 'audit:housekeeping';

    protected $description = 'Report audit availability, record suppressed events, clear expired password change data';

    public function handle(AuditAvailability $availability, SystemChainLimiter $limiter, AuditWriter $writer): int
    {
        $this->gauge($availability);
        $this->flushSuppressed($limiter, $writer);
        $this->clearExpiredPasswordChangeData();

        return 0;
    }

    /**
     * Written every minute, so that a missing line is noticed: no signal does not mean healthy.
     */
    private function gauge(AuditAvailability $availability): void
    {
        try {
            $state = $availability->auditState();

            Log::info('audit.unavailable', [
                'metric' => 'audit.unavailable',
                'value' => $state === null ? 0 : 1,
                'failure_class' => $state['failure_class'] ?? null,
                'storage_scope' => $state['storage_scope'] ?? null,
                'outage_id' => $state['outage_id'] ?? null,
                'duration_seconds' => $state === null ? null : now()->getTimestamp() - $state['started_at'],
            ]);
        } catch (Throwable $exception) {
            Log::critical('audit.unavailable', ['metric' => 'audit.unavailable', 'value' => 'unknown', 'exception' => $exception::class]);
        }
    }

    /**
     * The total goes to the log first: it must survive the chain being unwritable.
     */
    private function flushSuppressed(SystemChainLimiter $limiter, AuditWriter $writer): void
    {
        try {
            $pending = $limiter->pending();
        } catch (Throwable $exception) {
            Log::critical('audit.system_chain.suppressed_total', ['metric' => 'audit.system_chain.suppressed_total', 'exception' => $exception::class]);

            return;
        }

        foreach ($pending as $window => $count) {
            $startedAt = $limiter->iso($window);

            Log::critical('audit.system_chain.suppressed_total', [
                'metric' => 'audit.system_chain.suppressed_total',
                'window_started_at' => $startedAt,
                'suppressed_count' => $count,
            ]);

            $entry = AuditEntry::system(
                AuditEventType::EventsSuppressed,
                metadata: ['suppressed_count' => $count, 'window_started_at' => $startedAt],
                eventId: Uuid::uuid5(self::SUPPRESSED_NAMESPACE, $startedAt)->toString(),
            );

            try {
                SingleAttemptTransaction::run(DB::connection(AuditWriter::CONNECTION), fn () => $writer->append($entry, null, null));
                $limiter->forget($window);
            } catch (Throwable $exception) {
                Log::critical('audit.events_suppressed_write_failed', [
                    'metric' => 'audit.events_suppressed_write_failed',
                    'suppressed_count' => $count,
                    'exception' => $exception::class,
                ]);
            }
        }
    }

    /**
     * Tidying only: the API checks the expiry itself, so stopping this cannot make old data usable.
     */
    private function clearExpiredPasswordChangeData(): void
    {
        try {
            DB::connection(AuditWriter::CONNECTION)->update(
                'UPDATE users SET password_change_key_hash = NULL, password_change_previous_hash = NULL
                 WHERE password_change_key_hash IS NOT NULL AND password_changed_at <= clock_timestamp() - make_interval(mins => ?)',
                [config()->integer('audit.password_change_replay_minutes')],
            );
        } catch (Throwable $exception) {
            Log::error('audit.password_change_cleanup_failed', ['metric' => 'audit.password_change_cleanup_failed', 'exception' => $exception::class]);
        }
    }
}
