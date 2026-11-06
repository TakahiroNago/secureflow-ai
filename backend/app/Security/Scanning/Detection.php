<?php

namespace App\Security\Scanning;

/**
 * Where a rule matched, in characters of the original text. It holds no text.
 */
final readonly class Detection
{
    public function __construct(
        public Rule $rule,
        public int $start,
        public int $end,
    ) {}

    public function length(): int
    {
        return $this->end - $this->start;
    }

    public function overlaps(self $other): bool
    {
        return $this->start < $other->end && $other->start < $this->end;
    }
}
