<?php

namespace App\SelfTest;

use RuntimeException;

/**
 * Thrown at the end of a case to roll its transaction back. It carries the outcome out.
 */
final class RollbackSignal extends RuntimeException
{
    public function __construct(public readonly CaseOutcome $outcome)
    {
        parent::__construct('Self-test case finished: rolling back.');
    }
}
