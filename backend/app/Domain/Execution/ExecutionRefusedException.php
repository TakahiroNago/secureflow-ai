<?php

namespace App\Domain\Execution;

use RuntimeException;

/**
 * Only inside ExecutionService, to carry the reason out of the transaction so that the denial can be recorded.
 */
final class ExecutionRefusedException extends RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct($reason);
    }
}
