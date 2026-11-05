<?php

namespace App\Ai;

/**
 * Everything a provider receives. There is deliberately no field for tools, or for who is asking
 * (docs/security-design.md §6, §6.1), so neither can be sent by accident.
 */
final readonly class AiRequest
{
    public function __construct(
        public string $systemPrompt,
        public string $input,
        public int $maxOutputTokens,
        public int $timeoutSeconds,
    ) {}
}
