<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * What a scan decided, without any of the text (docs/database-design.md §3.10). Never changed.
 *
 * @property string $id
 * @property string $organization_id
 * @property string|null $user_id
 * @property string $target_type
 * @property string|null $target_id
 * @property string $ruleset_version
 * @property string|null $max_severity
 * @property string $decision
 * @property string|null $block_reason
 * @property string $masking_status
 * @property int $findings_count
 * @property int $duration_ms
 * @property CarbonInterface $created_at
 * @property-read Collection<int, SecurityFinding> $findings
 * @property-read User|null $user
 */
class SecurityScan extends Model
{
    use BelongsToOrganization, HasUuids;

    public const UPDATED_AT = null;

    public const TARGET_INPUT = 'input';

    public const TARGET_OUTPUT = 'output';

    public const TARGET_REVISION = 'revision';

    /**
     * @return HasMany<SecurityFinding, $this>
     */
    public function findings(): HasMany
    {
        return $this->hasMany(SecurityFinding::class, 'scan_id');
    }

    /**
     * Who asked for the scan. Null for a scan nobody asked for in a request of their own.
     *
     * @return BelongsTo<User, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['findings_count' => 'integer', 'duration_ms' => 'integer'];
    }
}
