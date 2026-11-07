<?php

namespace App\Ai;

use App\Ai\Contracts\AiProvider;
use App\Ai\Providers\MockAiProvider;
use App\Ai\Providers\OpenAiProvider;
use App\Support\Database\DatabaseCommandPolicy;
use RuntimeException;

/**
 * Which provider may run where (docs/architecture.md §11). The mock is for development and tests, and the real
 * provider needs its key, a reviewed model and the reviewed address. Production has no provider yet and refuses to start.
 * The configured value is not repeated in a message: a misplaced secret must not reach the logs.
 */
final class AiConfiguration
{
    /** The commands that serve work which can reach the AI. Maintenance commands such as migrate still run. */
    public const SERVING_COMMANDS = ['queue:work', 'queue:listen', 'schedule:work', 'schedule:run'];

    /** The only address (docs/security-design.md §6.1). OPENAI_BASE_URL can only agree with it. */
    public const OPENAI_BASE_URL = 'https://api.openai.com/v1';

    public static function assertValid(string $provider, string $environment): void
    {
        if ($provider !== 'mock' && $provider !== 'openai') {
            throw new RuntimeException('AI_PROVIDER has an unsupported value.');
        }

        // Neither in a public environment yet. The real provider has been reviewed for development only (§6.1).
        if (DatabaseCommandPolicy::isProductionEquivalent($environment)) {
            throw new RuntimeException('AI_PROVIDER='.$provider.' is not allowed in this environment.');
        }

        if ($provider === 'openai') {
            self::assertOpenAiConditions();
        }
    }

    public static function provider(string $provider, string $environment): AiProvider
    {
        self::assertValid($provider, $environment);

        return $provider === 'openai'
            ? new OpenAiProvider(config()->string('ai.openai.api_key'), config()->string('ai.openai.model'))
            : new MockAiProvider;
    }

    /**
     * The values are not repeated in a message: a misplaced secret must not reach the logs.
     */
    private static function assertOpenAiConditions(): void
    {
        $key = config()->string('ai.openai.api_key');

        if ($key === '' || preg_match('/\s/', $key) === 1) {
            throw new RuntimeException('AI_PROVIDER=openai needs OPENAI_API_KEY.');
        }

        if (! AiPricing::isReviewed(config()->string('ai.openai.model'))) {
            throw new RuntimeException('AI_PROVIDER=openai needs an OPENAI_MODEL that has been reviewed (docs/security-design.md §6.1).');
        }

        if (config()->string('ai.openai.base_url') !== self::OPENAI_BASE_URL) {
            throw new RuntimeException('AI_PROVIDER=openai needs the reviewed OPENAI_BASE_URL (docs/security-design.md §6.1).');
        }
    }
}
