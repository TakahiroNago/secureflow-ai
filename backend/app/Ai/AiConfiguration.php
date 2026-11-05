<?php

namespace App\Ai;

use App\Ai\Contracts\AiProvider;
use App\Ai\Providers\MockAiProvider;
use App\Support\Database\DatabaseCommandPolicy;
use RuntimeException;

/**
 * Which provider may run where (docs/architecture.md §11). The mock is for development and tests, and the
 * real provider does not exist before step 2-8, so production has no provider yet and refuses to start.
 * The configured value is not repeated in a message: a misplaced secret must not reach the logs.
 */
final class AiConfiguration
{
    /** The commands that serve work which can reach the AI. Maintenance commands such as migrate still run. */
    public const SERVING_COMMANDS = ['queue:work', 'queue:listen', 'schedule:work', 'schedule:run'];

    public static function assertValid(string $provider, string $environment): void
    {
        if ($provider === 'openai') {
            throw new RuntimeException('AI_PROVIDER=openai is not available before its conditions are met (docs/security-design.md §6.1).');
        }

        if ($provider !== 'mock') {
            throw new RuntimeException('AI_PROVIDER has an unsupported value.');
        }

        if (DatabaseCommandPolicy::isProductionEquivalent($environment)) {
            throw new RuntimeException('AI_PROVIDER=mock is not allowed in this environment.');
        }
    }

    public static function provider(string $provider, string $environment): AiProvider
    {
        self::assertValid($provider, $environment);

        return new MockAiProvider;
    }
}
