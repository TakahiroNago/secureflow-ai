<?php

namespace App\Domain\Security;

/**
 * docs/security-design.md §20. A finding starts open. Closing it (resolved or false positive) can be undone by
 * reopening it, and nothing else: the records of a scan are not rewritten, only this status beside them.
 */
enum FindingStatus: string
{
    case Open = 'open';
    case Acknowledged = 'acknowledged';
    case Resolved = 'resolved';
    case FalsePositive = 'false_positive';

    /**
     * @return list<self>
     */
    public function nextStatuses(): array
    {
        return match ($this) {
            self::Open => [self::Acknowledged, self::Resolved, self::FalsePositive],
            self::Acknowledged => [self::Resolved, self::FalsePositive, self::Open],
            self::Resolved, self::FalsePositive => [self::Open],
        };
    }

    public function canChangeTo(self $to): bool
    {
        return in_array($to, $this->nextStatuses(), true);
    }
}
