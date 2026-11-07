<?php

namespace App\Security\Policy;

/**
 * The server's allow list of what a task can be (docs/architecture.md §8). Permissions come from here and
 * never from what the AI asks for. A type that is not listed is not an action at all: callers treat it as a
 * schema violation. Raise the version whenever this list changes.
 */
final class ActionCatalog
{
    public const VERSION = '2026.11.1';

    private const ACTIONS = [
        'text.analyze' => ['decision' => PolicyDecision::Allowed, 'permissions' => ['ai.text.read']],
        'text.summarize' => ['decision' => PolicyDecision::Allowed, 'permissions' => ['ai.text.read']],
        'report.draft' => ['decision' => PolicyDecision::Allowed, 'permissions' => ['ai.text.read', 'report.draft.write']],
        'task.create' => ['decision' => PolicyDecision::Allowed, 'permissions' => ['task.write']],
        'email.send' => ['decision' => PolicyDecision::Forbidden, 'permissions' => ['external.email.send']],
        'file.delete' => ['decision' => PolicyDecision::Forbidden, 'permissions' => ['file.delete']],
        'shell.exec' => ['decision' => PolicyDecision::Forbidden, 'permissions' => ['system.shell']],
        'db.query' => ['decision' => PolicyDecision::Forbidden, 'permissions' => ['system.database']],
        'http.request' => ['decision' => PolicyDecision::Forbidden, 'permissions' => ['external.http']],
    ];

    /**
     * For the approval screen (docs/requirements.md §4.5). A label only: it decides nothing, and nothing runs yet.
     */
    private const AI_FEATURES = [
        'text.analyze' => 'テキスト分析（模擬実行）',
        'text.summarize' => 'テキスト要約（模擬実行）',
        'report.draft' => 'テキスト要約・レポート下書き生成（模擬実行）',
        'task.create' => 'タスク作成（模擬実行）',
    ];

    public static function aiFeature(string $actionType): string
    {
        return self::AI_FEATURES[$actionType] ?? 'なし（禁止された操作）';
    }

    public static function has(string $actionType): bool
    {
        return array_key_exists($actionType, self::ACTIONS);
    }

    /**
     * @return list<string>
     */
    public static function types(): array
    {
        return array_keys(self::ACTIONS);
    }

    public static function decision(string $actionType): ?PolicyDecision
    {
        return self::ACTIONS[$actionType]['decision'] ?? null;
    }

    /**
     * @return list<string> Empty for a type that is not listed.
     */
    public static function permissions(string $actionType): array
    {
        return self::ACTIONS[$actionType]['permissions'] ?? [];
    }
}
