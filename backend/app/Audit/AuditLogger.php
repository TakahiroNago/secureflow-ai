<?php

namespace App\Audit;

use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\RequestId;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Support\Facades\DB;
use LogicException;
use RedisException;
use Throwable;

/**
 * The entry point for audit records (docs/security-design.md §16.5).
 *
 * - recordInTransaction: same transaction as the business change. A failure propagates, and rolls
 *   the change back with it.
 * - recordAfterTransaction: outside any business transaction. Never throws; returns false on failure.
 */
class AuditLogger
{
    private ?string $chainInTransaction = null;

    public function __construct(
        private readonly AuditWriter $writer,
        private readonly TransactionBoundary $boundary,
        private readonly AuditAvailability $availability,
        private readonly SystemChainLimiter $limiter,
        private readonly RequestId $requestId,
    ) {}

    /**
     * @throws ServiceUnavailableException
     */
    public function recordInTransaction(AuditEntry $entry, string $outcomeOnFailure): int
    {
        if ($this->boundary->businessLevel() < 1) {
            throw new LogicException('recordInTransaction needs an open transaction.');
        }

        $chain = $entry->organizationId ?? 'system';
        // Two chains in one transaction can deadlock against the opposite order.
        if ($this->chainInTransaction !== null && $this->chainInTransaction !== $chain) {
            throw new LogicException('A transaction may record to one audit chain only.');
        }
        $this->chainInTransaction = $chain;

        try {
            return $this->writer->append($entry, $this->ip(), $this->requestId());
        } catch (Throwable $exception) {
            $this->availability->reportWriteFailure($exception, $entry, $outcomeOnFailure, $this->requestId());

            throw new ServiceUnavailableException('The audit record could not be written.', 0, $exception);
        }
    }

    /**
     * Runs in a one-attempt transaction of its own: outside a transaction Laravel would silently
     * reconnect and run a lost statement again.
     */
    public function recordAfterTransaction(AuditEntry $entry, string $outcomeOnFailure): bool
    {
        if ($this->boundary->businessLevel() !== 0) {
            throw new LogicException('recordAfterTransaction must run outside a business transaction.');
        }

        if ($this->isAnonymousOnSystemChain($entry) && ! $this->withinSystemChainLimit()) {
            return true;
        }

        try {
            SingleAttemptTransaction::run(
                DB::connection(AuditWriter::CONNECTION),
                fn () => $this->writer->append($entry, $this->ip(), $this->requestId()),
            );

            return true;
        } catch (Throwable $exception) {
            $this->availability->reportWriteFailure($exception, $entry, $outcomeOnFailure, $this->requestId());

            return false;
        }
    }

    public function transactionEnded(): void
    {
        if ($this->boundary->businessLevel() === 0) {
            $this->chainInTransaction = null;
        }
    }

    private function isAnonymousOnSystemChain(AuditEntry $entry): bool
    {
        return $entry->actorType === 'anonymous' && $entry->organizationId === null;
    }

    private function withinSystemChainLimit(): bool
    {
        try {
            return $this->limiter->allow();
        } catch (RedisException) {
            // Redis stopped after the entry point: this request goes unlimited, the next one gets 503.
            return true;
        }
    }

    private function ip(): ?string
    {
        // A command has a synthetic request with a loopback address, which says nothing. Only a
        // routed request has a client.
        if (request()->route() === null) {
            return null;
        }

        $ip = request()->ip();

        return is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : null;
    }

    private function requestId(): string
    {
        return $this->requestId->value();
    }
}
