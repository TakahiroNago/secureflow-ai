<?php

namespace App\SelfTest;

use RuntimeException;

/**
 * Answered as 409 (docs/api-design.md §3.7).
 */
final class SelfTestConflictException extends RuntimeException
{
    private function __construct(public readonly string $problemCode, public readonly string $detail)
    {
        parent::__construct($problemCode);
    }

    public static function running(): self
    {
        return new self('SELF_TEST_RUNNING', '自己診断を実行中です。完了してから再度実行してください。');
    }
}
