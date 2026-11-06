<?php

namespace App\Security\Scanning;

use RuntimeException;

/**
 * Scanning could not finish (docs/security-design.md §3.4). A fixed reason, and never any of the text.
 */
final class ScanFailure extends RuntimeException
{
    public const INVALID_ENCODING = 'invalid_encoding';

    public const TOO_LONG = 'too_long';

    public const TIMEOUT = 'timeout';

    public const PATTERN_ERROR = 'pattern_error';

    public const STILL_DETECTED = 'still_detected';

    public const COUNT_MISMATCH = 'count_mismatch';

    public function __construct(public readonly string $reason)
    {
        parent::__construct('Scanning failed: '.$reason);
    }
}
