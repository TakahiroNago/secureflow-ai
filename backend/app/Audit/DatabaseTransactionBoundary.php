<?php

namespace App\Audit;

use Illuminate\Support\Facades\DB;

final class DatabaseTransactionBoundary implements TransactionBoundary
{
    public function businessLevel(): int
    {
        return DB::connection(AuditWriter::CONNECTION)->transactionLevel();
    }
}
