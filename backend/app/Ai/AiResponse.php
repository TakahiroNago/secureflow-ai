<?php

namespace App\Ai;

/**
 * What the provider answered, not yet trusted in any way. See OutputValidator.
 */
final readonly class AiResponse
{
    public function __construct(
        public string $content,
        public ?AiTokens $tokens = null,
        public ?string $model = null,
        public ?string $requestId = null,
    ) {}
}
