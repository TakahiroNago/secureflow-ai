<?php

namespace App\Ai;

use RuntimeException;

/**
 * Says what kind of failure it was and nothing else: no request and no response text.
 */
final class AiProviderException extends RuntimeException
{
    public function __construct(public readonly AiFailure $failure)
    {
        parent::__construct('The AI provider failed: '.$failure->value);
    }
}
