<?php

namespace App\SelfTest\Cases;

use App\Ai\Providers\MockScenario;
use App\Security\Output\InvalidAiOutputException;
use App\Security\Policy\ActionCatalog;
use App\Security\Scanning\InputScanResult;
use App\SelfTest\CaseOutcome;
use App\SelfTest\ClosureCase;
use App\SelfTest\SelfTestContext;

/**
 * What the AI writes, checked the way the analysis checks it (docs/security-design.md §7). The answers are the
 * mock's scenarios: no provider is called. Nothing here touches the database.
 */
final class OutputCases
{
    private const CATEGORY = 'output';

    /**
     * @return list<ClosureCase>
     */
    public static function cases(): array
    {
        return [
            new ClosureCase('ST-07', self::CATEGORY, '不正な JSON・未知の項目・未知の操作・長すぎる値', '出力の検証で拒否され、何も保存されない', function (SelfTestContext $context): CaseOutcome {
                $checks = [];
                foreach ([MockScenario::MalformedJson, MockScenario::ExtraKeys, MockScenario::UnknownAction, MockScenario::Oversized] as $scenario) {
                    try {
                        $context->aiOutput($scenario);
                        $checks[$scenario->value.'_rejected'] = false;
                    } catch (InvalidAiOutputException) {
                        $checks[$scenario->value.'_rejected'] = true;
                    }
                }

                return CaseOutcome::all($checks, '4 件を拒否', ['scenarios' => 4]);
            }),

            new ClosureCase('ST-10', self::CATEGORY, 'HTML・スクリプトを含む AI 出力', 'タグが除去され、検出として記録される', function (SelfTestContext $context): CaseOutcome {
                $scanned = $context->aiOutput(MockScenario::ScriptTag);
                $description = $scanned->tasks[0]->description ?? '';

                return CaseOutcome::all([
                    'not_stopped' => ! $scanned->result->blocks(),
                    'no_tags_left' => ! str_contains($description, '<') && ! str_contains($description, '>') && ! str_contains($description, 'onerror'),
                    'markup_recorded' => self::hasCategory($scanned->result, 'markup'),
                ], 'タグを除去し、markup として記録', ['findings_count' => $scanned->result->findingsCount]);
            }),

            new ClosureCase('ST-15', self::CATEGORY, 'システムプロンプトの漏洩（カナリア）', 'カナリアを検出して分析を停止する', function (SelfTestContext $context): CaseOutcome {
                $scanned = $context->aiOutput(MockScenario::CanaryLeak);

                return CaseOutcome::all([
                    'stops' => $scanned->result->blocks(),
                    'reason_is_canary' => $scanned->result->blockReason === InputScanResult::REASON_CANARY,
                    'nothing_kept' => $scanned->tasks === [],
                ], '停止（CANARY_LEAK）', ['block_reason' => $scanned->result->blockReason]);
            }),

            new ClosureCase('ST-18', self::CATEGORY, 'AI が申告した権限の水増し', 'サーバーが導出した権限のみを採用し、不一致を記録する', function (SelfTestContext $context): CaseOutcome {
                $scanned = $context->aiOutput(MockScenario::PermissionInflation);
                $task = $scanned->tasks[0] ?? null;

                return CaseOutcome::all([
                    'not_stopped' => ! $scanned->result->blocks(),
                    'derived_only' => $task !== null && $task->permissions === ActionCatalog::permissions($task->actionType),
                    'claim_not_adopted' => $task !== null && ! in_array('system.shell', $task->permissions, true),
                    'mismatch_recorded' => self::hasCategory($scanned->result, 'permission_mismatch'),
                ], '導出権限のみ採用、不一致を記録', ['derived' => $task === null ? [] : $task->permissions]);
            }),

            new ClosureCase('ST-19', self::CATEGORY, 'AI 出力に含まれる秘密情報', '分析を停止し、何も保存しない', function (SelfTestContext $context): CaseOutcome {
                $scanned = $context->aiOutput(MockScenario::SecretLeak);

                return CaseOutcome::all([
                    'stops' => $scanned->result->blocks(),
                    'reason_is_secret' => $scanned->result->blockReason === InputScanResult::REASON_SECRET,
                    'nothing_kept' => $scanned->tasks === [],
                ], '停止（SECRET_DETECTED）', ['block_reason' => $scanned->result->blockReason]);
            }),
        ];
    }

    private static function hasCategory(InputScanResult $result, string $category): bool
    {
        foreach ($result->findings as $finding) {
            if ($finding->category === $category) {
                return true;
            }
        }

        return false;
    }
}
