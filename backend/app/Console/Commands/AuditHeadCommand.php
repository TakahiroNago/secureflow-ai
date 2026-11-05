<?php

namespace App\Console\Commands;

use App\Audit\AuditCanonicalizer;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * Prints chain heads as JSON Lines. Storing them outside the database is a manual step in the MVP,
 * and it is what makes a recomputed chain detectable, up to the time it was stored.
 */
final class AuditHeadCommand extends Command
{
    protected $signature = 'audit:head {--organization= : One organization} {--system : The system chain} {--all : Every chain}';

    protected $description = 'Print audit chain heads for storing outside the database';

    public function handle(): int
    {
        $query = DB::connection('pgsql_audit_read')->table('audit_chain_heads');

        if (! $this->option('all')) {
            $chains = array_values(array_filter([
                $this->option('system') ? AuditCanonicalizer::SYSTEM_CHAIN : null,
                is_string($this->option('organization')) ? $this->option('organization') : null,
            ]));

            if ($chains === []) {
                $this->error('Choose --organization, --system or --all.');

                return 2;
            }

            $query->whereIn('chain_id', $chains);
        }

        try {
            $rows = $query->orderBy('chain_id')->get(['chain_id', 'last_seq', 'last_hash']);
            $capturedAt = now()->utc()->toIso8601ZuluString();

            foreach ($rows as $row) {
                $this->line((string) json_encode([
                    'hash_version' => 1,
                    'chain_id' => $row->chain_id,
                    'last_seq' => (int) $row->last_seq,
                    'last_hash' => $row->last_hash,
                    'captured_at' => $capturedAt,
                ]));
            }
        } catch (Throwable $exception) {
            $this->error('Could not read the chain heads: '.$exception::class);

            return 2;
        }

        return 0;
    }
}
