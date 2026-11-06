<?php

namespace App\Security\Scanning\Detectors;

use App\Security\Scanning\ScanFailure;

/**
 * Every match in the text, or a failure. A pattern that gave up has not said "nothing here".
 */
final class Pattern
{
    /**
     * @return list<array{0: string, 1: int}> The text of each match, and its byte offset.
     *
     * @throws ScanFailure
     */
    public static function matches(string $pattern, string $subject): array
    {
        $found = preg_match_all($pattern, $subject, $matches, PREG_OFFSET_CAPTURE);

        if ($found === false || preg_last_error() !== PREG_NO_ERROR) {
            throw new ScanFailure(ScanFailure::PATTERN_ERROR);
        }

        return $matches[0];
    }
}
