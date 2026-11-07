<?php

namespace App\Console\Commands;

use App\Audit\AuditCanonicalizer;
use App\Audit\AuditChainVerifier;
use App\Audit\VerificationFailureReporter;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use stdClass;
use Throwable;

/**
 * Exit codes: 0 valid, 1 verification failed, 2 could not run (docs/security-design.md §16.6).
 * A failure neither repairs anything nor stops the service.
 */
final class AuditVerifyCommand extends Command
{
    protected $signature = 'audit:verify {--organization= : One organization} {--system : The system chain} {--all : Every chain} {--anchor= : A file written by audit:head}';

    protected $description = 'Recompute the audit hash chains';

    public function handle(AuditChainVerifier $verifier, VerificationFailureReporter $reporter): int
    {
        try {
            $anchors = $this->anchors();
            $chains = $this->chains($anchors);
        } catch (Throwable $exception) {
            $this->error('Could not read the chains: '.$exception::class);

            return 2;
        }

        if ($chains === []) {
            if ($this->option('all')) {
                $this->line('No chains yet: there is nothing to verify.');

                return 0;
            }

            $this->error('Choose --organization, --system or --all.');

            return 2;
        }

        $firstFailure = null;

        foreach ($chains as $chain) {
            try {
                $result = $verifier->verify($chain, $anchors[$chain] ?? null);
            } catch (Throwable $exception) {
                $this->error('Could not verify '.$chain.': '.$exception::class);

                return 2;
            }

            $this->line((string) json_encode($result));

            if (! $result['valid'] && $firstFailure === null) {
                $firstFailure = $result;
            }
        }

        if ($firstFailure === null) {
            return 0;
        }

        $reporter->report($firstFailure);

        return 1;
    }

    /**
     * @param  array<string, array{last_seq: int, last_hash: string}>  $anchors
     * @return list<string>
     */
    private function chains(array $anchors): array
    {
        if ($this->option('all')) {
            $rows = DB::connection('pgsql_audit_read')->select(
                'SELECT chain_id::text AS id FROM audit_chain_heads UNION SELECT DISTINCT chain_id::text FROM audit_logs ORDER BY 1'
            );

            // A chain can be gone altogether, rows and head. Then only a saved head still knows about it.
            $chains = array_unique([...array_map(fn (stdClass $row) => (string) $row->id, $rows), ...array_keys($anchors)]);
            sort($chains);

            return $chains;
        }

        $chains = [];
        if ($this->option('system')) {
            $chains[] = AuditCanonicalizer::SYSTEM_CHAIN;
        }
        if (is_string($this->option('organization'))) {
            $chains[] = $this->option('organization');
        }

        return $chains;
    }

    /**
     * @return array<string, array{last_seq: int, last_hash: string}>
     */
    private function anchors(): array
    {
        $file = $this->option('anchor');
        if (! is_string($file)) {
            return [];
        }

        $anchors = [];
        foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            /** @var array{chain_id: string, last_seq: int, last_hash: string} $row */
            $row = json_decode($line, true, 4, JSON_THROW_ON_ERROR);
            $anchors[$row['chain_id']] = ['last_seq' => (int) $row['last_seq'], 'last_hash' => $row['last_hash']];
        }

        return $anchors;
    }
}
