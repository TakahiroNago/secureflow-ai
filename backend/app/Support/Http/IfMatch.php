<?php

namespace App\Support\Http;

use Illuminate\Http\Request;

/**
 * If-Match: "<revision_no>" (docs/api-design.md §1).
 */
final class IfMatch
{
    /**
     * @throws PreconditionRequiredException
     */
    public static function revisionNo(Request $request): int
    {
        if (preg_match('/^"([1-9][0-9]{0,8})"$/D', (string) $request->header('If-Match'), $matches) !== 1) {
            throw new PreconditionRequiredException('If-Match is required.');
        }

        return (int) $matches[1];
    }
}
