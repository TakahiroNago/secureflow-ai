<?php

namespace App\Security\Scanning;

/**
 * PHP cannot stop a running pattern from outside, so this is checked between steps, and PCRE's own limits
 * and the limit on the input length bound what happens inside one (docs/security-design.md §3.4).
 */
final class ScanDeadline
{
    private readonly int $endsAtNanoseconds;

    public function __construct(float $seconds)
    {
        $this->endsAtNanoseconds = hrtime(true) + (int) ($seconds * 1_000_000_000);
    }

    /**
     * @throws ScanFailure
     */
    public function check(): void
    {
        if (hrtime(true) >= $this->endsAtNanoseconds) {
            throw new ScanFailure(ScanFailure::TIMEOUT);
        }
    }
}
