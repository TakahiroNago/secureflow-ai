<?php

namespace App\Http\Resources;

use App\Models\AuditLog;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * No hash, previous hash or chain id: the verification is what says something about those.
 *
 * @mixin AuditLog
 */
final class AuditLogResource extends JsonResource
{
    /** @var array<string, string> */
    public static array $actorNames = [];

    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'event_id' => $this->event_id,
            'chain_seq' => $this->chain_seq,
            'event_type' => $this->event_type,
            'result' => $this->result,
            'severity' => $this->severity,
            'actor' => [
                'type' => $this->actor_type,
                'id' => $this->actor_user_id,
                'name' => $this->actor_user_id === null ? null : (self::$actorNames[$this->actor_user_id] ?? null),
            ],
            'resource' => ['type' => $this->resource_type, 'id' => $this->resource_id],
            'ip_address' => $this->ip_address,
            'request_id' => $this->request_id,
            'metadata' => (object) $this->metadata,
            'occurred_at' => $this->occurred_at->toIso8601ZuluString(),
        ];
    }
}
