<?php

namespace App\Domain\Security;

use RuntimeException;

/**
 * Answered as 409 (docs/api-design.md §3.7). The message is fixed: it never carries the note or the finding.
 */
final class FindingConflictException extends RuntimeException
{
    private function __construct(public readonly string $problemCode, public readonly string $detail)
    {
        parent::__construct($problemCode);
    }

    public static function invalidTransition(): self
    {
        return new self('INVALID_STATUS_TRANSITION', '現在の対策状況からその状態には変更できません。最新の状態を確認してください。');
    }
}
