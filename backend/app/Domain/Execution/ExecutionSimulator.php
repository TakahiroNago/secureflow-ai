<?php

namespace App\Domain\Execution;

/**
 * What runs when a task is executed in the MVP: nothing outside this process (docs/security-design.md §8). There is
 * an entry for each allowed action, and none for a forbidden one, so there is no code that could send, delete or
 * query anything. It does not resolve anything from a string. The sentences are fixed and hold no task text, because
 * a result has no reason to be another copy of it.
 */
final class ExecutionSimulator
{
    private const OUTCOMES = [
        'text.analyze' => 'テキストを分析しました（模擬実行。外部への操作はありません）。',
        'text.summarize' => 'テキストを要約しました（模擬実行。外部への操作はありません）。',
        'report.draft' => 'レポートの下書きを生成しました（模擬実行。外部への操作はありません）。',
        'task.create' => 'タスクを作成しました（模擬実行。外部への操作はありません）。',
    ];

    /**
     * @return string|null Null when there is no handler for this action.
     */
    public static function run(string $actionType): ?string
    {
        return self::OUTCOMES[$actionType] ?? null;
    }
}
