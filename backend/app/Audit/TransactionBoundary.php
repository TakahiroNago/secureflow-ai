<?php

namespace App\Audit;

/**
 * How many business transactions are open. The database cannot tell: a function always runs inside
 * some transaction. Tests with DatabaseTransactions supply their own base level
 * (docs/test-strategy.md §15). The production class never looks at the environment.
 */
interface TransactionBoundary
{
    public function businessLevel(): int;
}
