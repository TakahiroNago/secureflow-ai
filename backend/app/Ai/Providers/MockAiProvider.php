<?php

namespace App\Ai\Providers;

use App\Ai\AiFailure;
use App\Ai\AiProviderException;
use App\Ai\AiRequest;
use App\Ai\AiResponse;
use App\Ai\Contracts\AiProvider;
use App\Ai\PromptBuilder;

/**
 * Fixed answers, with no I/O. The scenario is a constructor argument and nothing else: a test passes it, and
 * the application always gets Normal. Nothing in a request or the environment can select another one, so
 * what a user types cannot change how this behaves.
 */
final class MockAiProvider implements AiProvider
{
    public function __construct(private readonly MockScenario $scenario = MockScenario::Normal) {}

    public function generate(AiRequest $request): AiResponse
    {
        return new AiResponse(match ($this->scenario) {
            MockScenario::Normal => $this->tasks($this->task()),
            MockScenario::MalformedJson => '{"tasks": [{"title": "途中で切れた',
            MockScenario::ExtraKeys => $this->tasks($this->task(['unexpected' => 'value'])),
            MockScenario::Oversized => $this->tasks($this->task(['title' => str_repeat('あ', 101)])),
            MockScenario::ScriptTag => $this->tasks($this->task(['description' => '問い合わせ内容を要約する。<script>alert(1)</script><img src=x onerror=alert(1)>'])),
            MockScenario::ForbiddenAction => $this->tasks($this->task(['action_type' => 'email.send']), $this->task(['action_type' => 'shell.exec'])),
            MockScenario::UnknownAction => $this->tasks($this->task(['action_type' => 'payment.transfer'])),
            MockScenario::PermissionInflation => $this->tasks($this->task(['requested_permissions' => ['system.shell', 'external.http', 'admin.all']])),
            // Built here so that the repository holds nothing shaped like a key for secret scanners to find.
            MockScenario::SecretLeak => $this->tasks($this->task(['description' => 'キーは sk-'.str_repeat('a1B2', 12).' です'])),
            // What a model does when it repeats its prompt. Tests choose this scenario: a request cannot.
            MockScenario::CanaryLeak => $this->tasks($this->task(['description' => preg_match(PromptBuilder::CANARY_PATTERN, $request->systemPrompt, $match) === 1 ? $match[0] : 'no canary was given'])),
            MockScenario::Timeout => throw new AiProviderException(AiFailure::Timeout),
            MockScenario::RateLimited => throw new AiProviderException(AiFailure::RateLimited),
            MockScenario::ServerError => throw new AiProviderException(AiFailure::ServerError),
        });
    }

    /**
     * @param  array<string, mixed>  ...$tasks
     */
    private function tasks(array ...$tasks): string
    {
        return json_encode(['tasks' => $tasks], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
    }

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    private function task(array $overrides = []): array
    {
        return [
            'title' => '問い合わせの要約',
            'description' => '問い合わせ内容を要約する。',
            'action_type' => 'text.summarize',
            'steps' => ['内容を読む', '要点をまとめる'],
            'priority' => 'medium',
            'requested_permissions' => ['ai.text.read'],
            'target_data' => '問い合わせ本文',
            'impact_summary' => '外部への影響はない。',
            ...$overrides,
        ];
    }
}
