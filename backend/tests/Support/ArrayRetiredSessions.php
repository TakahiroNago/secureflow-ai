<?php

namespace Tests\Support;

use App\Domain\Auth\RetiredSessions;

/**
 * Stands in for Redis in tests with array sessions. PasswordChangeFailureTest covers the real one.
 */
final class ArrayRetiredSessions implements RetiredSessions
{
    /** @var array<string, true> */
    public array $ids = [];

    public function retire(string $sessionId): void
    {
        $this->ids[$sessionId] = true;
    }

    public function claim(string $sessionId): bool
    {
        if (isset($this->ids[$sessionId])) {
            return false;
        }

        $this->ids[$sessionId] = true;

        return true;
    }

    public function restore(string $sessionId): void
    {
        unset($this->ids[$sessionId]);
    }

    public function isRetired(string $sessionId): bool
    {
        return isset($this->ids[$sessionId]);
    }
}
