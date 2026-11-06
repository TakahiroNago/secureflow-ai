<?php

namespace App\Security\Scanning\Injection;

use App\Security\Scanning\ScanAction;
use App\Security\Scanning\Severity;

/**
 * Severity and action are null when nothing matched. A failure is a block with no hits, and a reason.
 */
final readonly class InjectionResult
{
    /**
     * @param  list<InjectionHit>  $hits
     */
    public function __construct(
        public ?Severity $severity,
        public ?ScanAction $action,
        public array $hits,
        public ?string $failureReason = null,
    ) {}

    public function blocks(): bool
    {
        return $this->action === ScanAction::Block;
    }
}
