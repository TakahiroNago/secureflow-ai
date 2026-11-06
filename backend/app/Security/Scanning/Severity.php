<?php

namespace App\Security\Scanning;

enum Severity: string
{
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    /** One level up, and Critical stays Critical. */
    public function raised(): self
    {
        return match ($this) {
            self::Low => self::Medium,
            self::Medium => self::High,
            self::High, self::Critical => self::Critical,
        };
    }

    public static function higher(?self $a, ?self $b): ?self
    {
        if ($a === null || $b === null) {
            return $a ?? $b;
        }

        return $a->rank() >= $b->rank() ? $a : $b;
    }

    public function rank(): int
    {
        return match ($this) {
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }
}
