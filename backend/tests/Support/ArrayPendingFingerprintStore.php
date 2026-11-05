<?php

namespace Tests\Support;

use App\Domain\Auth\PendingFingerprintStore;
use App\Support\Http\ServiceUnavailableException;
use Closure;

/**
 * Stands in for Redis in tests that are not about Redis. PasswordChangeFailureTest covers the real one.
 */
final class ArrayPendingFingerprintStore implements PendingFingerprintStore
{
    /** @var array<string, string> */
    public array $values = [];

    /** @var array<string, array{owner: string, until: int}> */
    public array $owners = [];

    public bool $failPrepare = false;

    public bool $failWrite = false;

    /** Runs where a competing request could commit: after the row was read, before its lock. */
    public ?Closure $beforePrepare = null;

    public function prepare(): void
    {
        if ($this->beforePrepare !== null) {
            ($this->beforePrepare)();
        }

        if ($this->failPrepare) {
            throw new ServiceUnavailableException('prepare failed');
        }
    }

    public function write(string $sessionId, string $fingerprint, string $owner): void
    {
        if ($this->failWrite) {
            throw new ServiceUnavailableException('write failed');
        }

        $this->values[$sessionId] = $fingerprint;
        $this->owners[$sessionId] = ['owner' => $owner, 'until' => now()->getTimestamp() + self::OWNER_SECONDS];
    }

    public function read(string $sessionId): ?string
    {
        return $this->values[$sessionId] ?? null;
    }

    public function mayRotate(string $sessionId, ?string $owner): bool
    {
        $current = $this->owners[$sessionId] ?? null;

        return ! ($current !== null && $current['owner'] !== $owner && $current['until'] > now()->getTimestamp());
    }

    public function giveUpOwnership(string $sessionId): void
    {
        unset($this->owners[$sessionId]);
    }
}
