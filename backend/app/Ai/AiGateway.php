<?php

namespace App\Ai;

use App\Ai\Contracts\AiProvider;
use Illuminate\Support\Sleep;

/**
 * The only way to call a provider. The usage limits and the usage log arrive with the real provider in
 * step 2-8. What it returns is untrusted: see OutputValidator.
 */
final class AiGateway
{
    private const MAX_ATTEMPTS = 3;

    private const FIRST_BACKOFF_SECONDS = 1;

    public function __construct(
        private readonly AiProvider $provider,
        private readonly int $timeoutSeconds,
        private readonly int $maxOutputTokens,
    ) {}

    /**
     * @throws AiProviderException The last failure, once retrying is over or pointless.
     */
    public function generate(string $systemPrompt, string $input): AiResponse
    {
        $request = new AiRequest($systemPrompt, $input, $this->maxOutputTokens, $this->timeoutSeconds);

        for ($attempt = 1; ; $attempt++) {
            try {
                return $this->provider->generate($request);
            } catch (AiProviderException $exception) {
                if ($attempt >= self::MAX_ATTEMPTS || ! $exception->failure->isRetryable()) {
                    throw $exception;
                }
            }

            Sleep::for(self::FIRST_BACKOFF_SECONDS * 2 ** ($attempt - 1))->seconds();
        }
    }

    /**
     * The longest one call can take, when every attempt times out. A job that calls this needs a longer
     * time limit than this (step 1-6), or it would be killed while still retrying.
     */
    public function worstCaseSeconds(): int
    {
        $backoff = 0;
        for ($attempt = 1; $attempt < self::MAX_ATTEMPTS; $attempt++) {
            $backoff += self::FIRST_BACKOFF_SECONDS * 2 ** ($attempt - 1);
        }

        return self::MAX_ATTEMPTS * $this->timeoutSeconds + $backoff;
    }
}
