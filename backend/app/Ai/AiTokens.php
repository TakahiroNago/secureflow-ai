<?php

namespace App\Ai;

/**
 * What a call used, as the provider counted it. The mock has none.
 */
final readonly class AiTokens
{
    public function __construct(
        public int $input,
        public int $output,
        public int $total,
    ) {}
}
