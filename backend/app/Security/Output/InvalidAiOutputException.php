<?php

namespace App\Security\Output;

use RuntimeException;

/**
 * AI_INVALID_OUTPUT (docs/security-design.md §7), which is not retried. It carries a fixed reason and a
 * position such as tasks[2].title. Nothing the AI wrote, not even an unknown key's name, gets into it.
 */
final class InvalidAiOutputException extends RuntimeException
{
    public const CODE = 'AI_INVALID_OUTPUT';

    public function __construct(public readonly string $reason, public readonly string $position = '')
    {
        parent::__construct(self::CODE.': '.$reason.($position === '' ? '' : ' at '.$position));
    }
}
