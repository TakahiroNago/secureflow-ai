<?php

namespace App\Audit;

use Illuminate\Support\Facades\Log;

/**
 * What a broken chain leaves behind, whoever found it (docs/security-design.md §16.6). The log does not depend on the
 * database. One attempt at the chain: its failure is not recorded again, and changes no answer.
 */
final readonly class VerificationFailureReporter
{
    public function __construct(private AuditLogger $logger) {}

    /**
     * @param  array{chain_id: string, first_broken_seq: ?int, reason_code: ?string}  $result
     */
    public function report(array $result): void
    {
        Log::critical('audit.verification_failed', [
            'metric' => 'audit.verification_failed',
            'chain_id' => $result['chain_id'],
            'first_broken_seq' => $result['first_broken_seq'],
            'reason_code' => $result['reason_code'],
        ]);

        $this->logger->recordAfterTransaction(AuditEntry::system(AuditEventType::VerificationFailed, result: 'failure', metadata: [
            'chain_id' => $result['chain_id'],
            'first_broken_seq' => (int) $result['first_broken_seq'],
            'reason_code' => (string) $result['reason_code'],
        ]), 'verification_failure_unrecorded');
    }
}
