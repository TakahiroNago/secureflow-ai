<?php

namespace App\Ai;

enum AiFailure: string
{
    case Timeout = 'timeout';
    case RateLimited = 'rate_limited';
    case ServerError = 'server_error';
    case Rejected = 'rejected';

    /**
     * docs/security-design.md §6. A rejected request would be rejected again.
     */
    public function isRetryable(): bool
    {
        return $this !== self::Rejected;
    }
}
