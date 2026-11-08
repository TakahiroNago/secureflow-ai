<?php

namespace App\SelfTest;

use App\SelfTest\Cases\AuditCases;
use App\SelfTest\Cases\AuthorizationCases;
use App\SelfTest\Cases\InputCases;
use App\SelfTest\Cases\OutputCases;
use App\SelfTest\Cases\WorkflowCases;

/**
 * The cases of docs/test-strategy.md §5 that the application can check on itself, and the ones that only CI can.
 */
final class SelfTestCases
{
    /** What needs HTTP, a browser, a second process or the real network: verified in CI, named on the screen. */
    public const CI_ONLY = [
        'ST-05' => '未認証の API アクセスが 401 になる',
        'ST-11' => '大量の要求が 429 になる',
        'ST-23' => '別組織のデータに全エンドポイントで 404 になる',
        'ST-24' => 'ログインの連続失敗でロックされる',
        'ST-25' => 'ログイン前後でセッション ID が再生成される',
        'ST-26' => 'CSRF トークンのない変更が 419 になる',
        'ST-27' => '存在する・しないメールアドレスで応答が同じになる',
        'ST-29' => '例外時の応答とログに内部情報がない',
        'ST-31' => 'AI への要求に tools がなく、送信先が固定されている',
        'ST-32' => 'SQL インジェクションの文字列が無害化される',
        'ST-33' => '実行中のワーカー停止が停滞回収で Failed になる',
        'ST-34' => '全ルートに認証と Policy がある',
        'ST-39' => '検出限界の注意文言が常に返る',
    ];

    /**
     * @return list<SelfTestCase>
     */
    public static function all(): array
    {
        return [
            ...InputCases::cases(),
            ...OutputCases::cases(),
            ...AuthorizationCases::cases(),
            ...WorkflowCases::cases(),
            ...AuditCases::cases(),
        ];
    }
}
