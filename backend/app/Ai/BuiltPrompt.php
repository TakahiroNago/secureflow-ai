<?php

namespace App\Ai;

/**
 * What goes to the AI for one request, and the canary to look for in its answer. None of this is stored or logged.
 */
final readonly class BuiltPrompt
{
    public function __construct(
        public string $systemPrompt,
        public string $input,
        public string $canary,
    ) {}
}
