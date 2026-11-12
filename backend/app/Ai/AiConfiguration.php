<?php

namespace App\Ai;

use App\Ai\Contracts\AiProvider;
use App\Ai\Providers\MockAiProvider;
use App\Ai\Providers\OpenAiProvider;
use App\Support\Database\DatabaseCommandPolicy;
use RuntimeException;

/**
 * Which provider may run where (docs/architecture.md §11). The mock runs anywhere, the public environment included
 * (docs/security-design.md §22, step 5-1). The real provider needs its key, a reviewed model and the reviewed address,
 * and has been reviewed for development only: a production-equivalent environment refuses to start with it until the
 * re-evaluation of §22 A-5 (step 5-5). The configured value is not repeated in a message: a misplaced secret must not
 * reach the logs.
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

        if ($provider === 'openai') {
            // Reviewed for development only (§6.1 decision 4, §22 A-5). Anything not known to be safe counts as production.
            if (DatabaseCommandPolicy::isProductionEquivalent($environment)) {
                throw new RuntimeException('AI_PROVIDER=openai is not allowed in this environment.');
            }

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
