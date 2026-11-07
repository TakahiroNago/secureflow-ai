<?php

namespace App\Ai;

/**
 * An estimate, in millionths of a dollar, from the prices read on 2026-11-07 (docs/security-design.md §6.1). Cached
 * input is counted at the full price, so it can only be too high. The bill is what OpenAI says it is. A model that has
 * not been reviewed cannot be configured at all (AiConfiguration).
 */
final class AiPricing
{
    /** USD millionths per million tokens: input, output. */
    private const PRICES = ['gpt-6-luna' => [100_000, 500_000]];

    public static function isReviewed(string $model): bool
    {
        return array_key_exists($model, self::PRICES);
    }

    public static function estimateMicros(string $model, AiTokens $tokens): ?int
    {
        if (! self::isReviewed($model)) {
            return null;
        }

        [$input, $output] = self::PRICES[$model];

        return (int) round(($tokens->input * $input + $tokens->output * $output) / 1_000_000);
    }
}
