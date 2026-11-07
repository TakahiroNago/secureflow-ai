<?php

namespace App\Ai;

use App\Ai\Contracts\AiProvider;
use Illuminate\Support\Sleep;

/**
 * The only way to call a provider. What it returns is untrusted: see OutputValidator.
 */
final class AiGateway
{
    private const MAX_ATTEMPTS = 3;

    private const FIRST_BACKOFF_SECONDS = 1;

    /** A provider's Retry-After is followed up to this: the job has a time limit. */
    private const MAX_WAIT_SECONDS = 5;

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

                $backoff = self::FIRST_BACKOFF_SECONDS * 2 ** ($attempt - 1);
                Sleep::for(min(max($backoff, $exception->retryAfterSeconds ?? 0), self::MAX_WAIT_SECONDS))->seconds();
            }
        }
    }

    /**
     * The longest one call can take, when every attempt times out. A job that calls this needs a longer
     * time limit than this (step 1-6), or it would be killed while still retrying.
     */
    public function worstCaseSeconds(): int
    {
        return self::MAX_ATTEMPTS * $this->timeoutSeconds + (self::MAX_ATTEMPTS - 1) * self::MAX_WAIT_SECONDS;
    }
}
