<?php

namespace App\Security\Scanning\Injection;

use App\Security\Scanning\Severity;

/**
 * Which rule matched and where, in characters of the original. It holds no text.
 */
final readonly class InjectionHit
{
    public function __construct(
        public string $ruleId,
        public string $category,
        public Severity $severity,
        public int $start,
        public int $end,
        public bool $disguised,
    ) {}
}
