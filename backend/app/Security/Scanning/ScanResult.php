<?php

namespace App\Security\Scanning;

/**
 * What came of a scan. It never holds the original text. The masked text is null whenever the decision is
 * block, so the surroundings of a secret cannot travel any further (docs/api-design.md §3.3).
 */
final readonly class ScanResult
{
    public const MASKING_NOT_REQUIRED = 'not_required';

    public const MASKING_DONE = 'masked';

    public const MASKING_FAILED = 'failed';

    /**
     * @param  list<Detection>  $detections
     */
    public function __construct(
        public ScanDecision $decision,
        public string $maskingStatus,
        public ?string $maskedText,
        public array $detections,
        public int $removedInvisible,
        public ?string $failureReason = null,
    ) {}

    public function maxSeverity(): ?Severity
    {
        $max = null;

        foreach ($this->detections as $detection) {
            $severity = $detection->rule->severity();

            if ($max === null || $severity->rank() > $max->rank()) {
                $max = $severity;
            }
        }

        return $max;
    }
}
