<?php

namespace App\Support\Http;

use Illuminate\Support\Str;

/**
 * One id for one request or job: the trace_id of an error answer, the trace_id of each log line, and the request_id of
 * each audit record. Someone who reports an error can be found in the logs by what the screen told them.
 */
final class RequestId
{
    private ?string $value = null;

    public function value(): string
    {
        return $this->value ??= (string) Str::uuid7();
    }
}
