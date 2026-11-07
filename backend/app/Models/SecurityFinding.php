<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * One thing a scan found (docs/database-design.md §3.11). The message is a fixed sentence, and an excerpt
 * only ever comes from masked text that is being kept anyway. Only the status columns ever change (step 2-10),
 * and the application role can update nothing else.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $scan_id
 * @property string $category
 * @property string $rule_id
 * @property string $severity
 * @property string $action
 * @property string $message
 * @property string|null $masked_excerpt
 * @property string|null $field_path
 * @property int|null $position_start
 * @property int|null $position_end
 * @property string $status
 * @property string|null $status_note
 * @property string|null $status_changed_by
 * @property CarbonInterface|null $status_changed_at
 * @property CarbonInterface $created_at
 * @property-read SecurityScan $scan
 * @property-read User|null $statusChangedBy
 */
class SecurityFinding extends Model
{
    use BelongsToOrganization, HasUuids;

    /**
     * @return BelongsTo<SecurityScan, $this>
     */
    public function scan(): BelongsTo
    {
        return $this->belongsTo(SecurityScan::class, 'scan_id');
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function statusChangedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'status_changed_by');
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['position_start' => 'integer', 'position_end' => 'integer', 'status_changed_at' => 'datetime'];
    }
}
