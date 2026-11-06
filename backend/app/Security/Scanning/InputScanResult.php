<?php

namespace App\Security\Scanning;

use LogicException;

/**
 * The whole answer of a scan. It never holds the original text, and there is no masked text after a block,
 * so that the surroundings of a secret cannot travel any further (docs/api-design.md §3.3).
 */
final readonly class InputScanResult
{
    public const REASON_MASK_FAILED = 'MASK_FAILED';

    public const REASON_SECRET = 'SECRET_DETECTED';

    public const REASON_INJECTION = 'INJECTION_HIGH';

    /**
     * @param  array<string, string>|null  $maskedFields  Null exactly when the decision is block.
     * @param  list<InputFinding>  $findings  At most InputScanner::MAX_FINDINGS, what stops the work first.
     * @param  int  $findingsCount  How many there were in all.
     */
    public function __construct(
        public ScanDecision $decision,
        public ?Severity $maxSeverity,
        public string $maskingStatus,
        public ?string $blockReason,
        public ?array $maskedFields,
        public array $findings,
        public int $findingsCount,
        public int $durationMs,
        public string $rulesetVersion,
        public ?string $failureReason = null,
    ) {}

    public function blocks(): bool
    {
        return $this->decision === ScanDecision::Block;
    }

    /**
     * @throws LogicException when the scan stopped, which the caller has to have dealt with
     */
    public function maskedText(): string
    {
        return $this->maskedFields[InputScanner::SINGLE_TEXT] ?? throw new LogicException('A blocked scan has no masked text.');
    }
}
