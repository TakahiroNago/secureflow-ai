<?php

namespace App\Audit;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * The only caller of audit_append(). An architecture test keeps it that way.
 */
class AuditWriter
{
    public const CONNECTION = 'pgsql';

    public function append(AuditEntry $entry, ?string $ip, ?string $requestId): int
    {
        $row = DB::connection(self::CONNECTION)->selectOne(
            'SELECT public.audit_append(?::uuid, ?::uuid, ?, ?::uuid, ?, ?, ?::uuid, ?, ?, ?::inet, ?::uuid, ?::jsonb) AS seq',
            [
                $entry->eventId ?? (string) Str::uuid7(),
                $entry->organizationId,
                $entry->actorType,
                $entry->actorUserId,
                $entry->type->value,
                $entry->resourceType,
                $entry->resourceId,
                $entry->result,
                $entry->type->severity(),
                $ip,
                $requestId,
                $entry->metadata === [] ? '{}' : json_encode($entry->metadata, JSON_THROW_ON_ERROR),
            ],
        );

        return (int) $row->seq;
    }
}
