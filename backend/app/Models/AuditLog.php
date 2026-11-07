<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use LogicException;

/**
 * For reading an organization's audit log. Rows are only ever written by audit_append(), through AuditLogger. A row of
 * the system chain has no organization, so the organization scope can never return one (docs/database-design.md §3.12.1).
 *
 * @property int $id
 * @property string $event_id
 * @property string|null $organization_id
 * @property int $chain_seq
 * @property string $actor_type
 * @property string|null $actor_user_id
 * @property string $event_type
 * @property string|null $resource_type
 * @property string|null $resource_id
 * @property string $result
 * @property string|null $severity
 * @property string|null $ip_address
 * @property string|null $request_id
 * @property array<string, mixed> $metadata
 * @property CarbonInterface $occurred_at
 */
class AuditLog extends Model
{
    use BelongsToOrganization;

    public $timestamps = false;

    protected static function booted(): void
    {
        $refuse = function (): never {
            throw new LogicException('The audit log is written by audit_append() only.');
        };

        static::saving($refuse);
        static::deleting($refuse);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['chain_seq' => 'integer', 'metadata' => 'array', 'occurred_at' => 'datetime'];
    }
}
