<?php

namespace App\Console\Commands;

use App\Audit\AuditAvailability;
use Illuminate\Console\Command;
use Throwable;

/**
 * For operators and monitoring, not exposed over HTTP. Readiness stays 200 for most audit failures,
 * so it cannot answer this question. Exit codes: 0 available, 1 Audit unavailable, 2 unknown.
 */
final class AuditStatusCommand extends Command
{
    protected $signature = 'audit:status';

    protected $description = 'Report whether the audit log can be written';

    public function handle(AuditAvailability $availability): int
    {
        try {
            $state = $availability->auditState();
        } catch (Throwable $exception) {
            $this->error('Unknown: the state could not be read ('.$exception::class.').');

            return 2;
        }

        if ($state === null) {
            $this->info('available');

            return 0;
        }

        $this->line((string) json_encode([
            'status' => 'unavailable',
            'outage_id' => $state['outage_id'],
            'failure_class' => $state['failure_class'],
            'storage_scope' => $state['storage_scope'],
            'duration_seconds' => now()->getTimestamp() - $state['started_at'],
        ]));

        return 1;
    }
}
