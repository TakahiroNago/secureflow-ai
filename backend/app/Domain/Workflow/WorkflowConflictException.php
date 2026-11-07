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

    public static function approvalNotValid(): self
    {
        return new self('APPROVAL_NOT_VALID', '有効な承認がありません。');
    }

    public static function executionAlreadyExists(): self
    {
        return new self('EXECUTION_ALREADY_EXISTS', 'この承認はすでに実行に使われています。もう一度実行するには、下書きに戻して再度承認を受けてください。');
    }

    public static function policyViolation(): self
    {
        return new self('POLICY_VIOLATION', '現在のポリシーで禁止された操作が含まれているため実行できません。');
    }

    public static function policyVersionChanged(): self
    {
        return new self('POLICY_VIOLATION', '承認の後にポリシーが変更されたため実行できません。編集して保存し、再度承認を受けてください。');
    }

    public static function planHashMismatch(): self
    {
        return new self('PLAN_HASH_MISMATCH', '承認対象の内容が変更されています。最新の内容を確認してください。');
    }

    public static function alreadyDecided(): self
    {
        return new self('ALREADY_DECIDED', 'このリビジョンはすでに承認または却下されています。');
    }

    public static function scanRequired(): self
    {
        return new self('SCAN_REQUIRED', '未検査のリビジョンは提出、承認できません。編集して保存すると計画全体を検査します。');
    }

    public static function scanBlocked(): self
    {
        return new self('SCAN_BLOCKED', '検査で停止と判定されたリビジョンは提出、承認できません。');
    }

    public static function forbiddenActionPresent(): self
    {
        return new self('FORBIDDEN_ACTION_PRESENT', '禁止された操作を含むワークフローは提出、承認できません。');
    }
}
