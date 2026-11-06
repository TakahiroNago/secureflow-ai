<?php

namespace App\Audit;

use App\Models\User;

/**
 * What to record. The actor can only come from a verified User or be system or anonymous: there is
 * no way to name an actor by id, so request data cannot choose one (docs/security-design.md §16.5).
 */
final readonly class AuditEntry
{
    /**
     * @param  array<string, string|int|bool>  $metadata
     */
    private function __construct(
        public AuditEventType $type,
        public ?string $organizationId,
        public string $actorType,
        public ?string $actorUserId,
        public string $result,
        public ?string $resourceType,
        public ?string $resourceId,
        public array $metadata,
        public ?string $eventId = null,
    ) {}

    /**
     * @param  array<string, string|int|bool>  $metadata
     */
    public static function byUser(AuditEventType $type, User $user, string $result = 'success', array $metadata = []): self
    {
        return new self($type, $user->organization_id, 'user', $user->id, $result, null, null, self::allowed($type, $metadata));
    }

    /**
     * @param  array<string, string|int|bool>  $metadata
     */
    public static function byUserOn(AuditEventType $type, User $user, string $resourceType, string $resourceId, array $metadata = [], string $result = 'success'): self
    {
        return new self($type, $user->organization_id, 'user', $user->id, $result, $resourceType, $resourceId, self::allowed($type, $metadata));
    }

    /**
     * An attempt with no authenticated actor. A null target means no organization: the system chain.
     *
     * @param  array<string, string|int|bool>  $metadata
     */
    public static function anonymous(AuditEventType $type, ?User $target, string $result, array $metadata = []): self
    {
        return new self(
            $type,
            $target?->organization_id,
            'anonymous',
            null,
            $result,
            $target === null ? null : 'user',
            $target?->id,
            self::allowed($type, $metadata),
        );
    }

    /**
     * @param  array<string, string|int|bool>  $metadata
     */
    public static function system(AuditEventType $type, ?User $target = null, string $result = 'success', array $metadata = [], ?string $eventId = null): self
    {
        return new self(
            $type,
            $target?->organization_id,
            'system',
            null,
            $result,
            $target === null ? null : 'user',
            $target?->id,
            self::allowed($type, $metadata),
            $eventId,
        );
    }

    public function chainKind(): string
    {
        return $this->organizationId === null ? 'system' : 'organization';
    }

    /**
     * @param  array<string, string|int|bool>  $metadata
     * @return array<string, string|int|bool>
     */
    private static function allowed(AuditEventType $type, array $metadata): array
    {
        return array_intersect_key($metadata, array_flip($type->allowedMetadata()));
    }
}
