<?php

namespace App\Ai;

enum AiFailure: string
{
    case Timeout = 'timeout';
    case RateLimited = 'rate_limited';
    case ServerError = 'server_error';
    case Rejected = 'rejected';
    case Unauthorized = 'unauthorized';
    case QuotaExceeded = 'quota_exceeded';
    case Refused = 'refused';
    case Incomplete = 'incomplete';
    case Malformed = 'malformed';

    /**
     * docs/security-design.md §6. Only what can pass a moment later. Billing, a key or a request will not change by
     * themselves, and a refusal or a cut-off answer would only cost as much again.
     */
    public function isRetryable(): bool
    {
        return in_array($this, [self::Timeout, self::RateLimited, self::ServerError], true);
    }

    /**
     * The call worked, and what came back cannot be used.
     */
    public function isInvalidOutput(): bool
    {
        return in_array($this, [self::Refused, self::Incomplete, self::Malformed], true);
    }
}
