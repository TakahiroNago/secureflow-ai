<?php

namespace App\Domain\Workflow;

use RuntimeException;

/**
 * Answered as 409 (docs/api-design.md). The message is fixed: it never carries workflow content.
 */
final class WorkflowConflictException extends RuntimeException
{
    private function __construct(public readonly string $problemCode, public readonly string $detail)
    {
        parent::__construct($problemCode);
    }

    public static function invalidState(): self
    {
        return new self('WORKFLOW_INVALID_STATE', '現在の状態ではこの操作を行えません。');
    }

    public static function revisionConflict(): self
    {
        return new self('REVISION_CONFLICT', '内容が更新されています。再読み込みしてください。');
    }
}
