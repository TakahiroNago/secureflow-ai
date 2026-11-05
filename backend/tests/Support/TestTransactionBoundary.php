<?php

namespace Tests\Support;

use App\Audit\AuditWriter;
use App\Audit\TransactionBoundary;
use Illuminate\Support\Facades\DB;

/**
 * Subtracts the transaction DatabaseTransactions opens, so the application sees the levels it would
 * see in production. Lives in tests/, so production cannot load it, and the production boundary has
 * no environment branch (docs/test-strategy.md §15).
 */
final class TestTransactionBoundary implements TransactionBoundary
{
    public function __construct(private readonly int $base) {}

    public function businessLevel(): int
    {
        return max(0, DB::connection(AuditWriter::CONNECTION)->transactionLevel() - $this->base);
    }
}
