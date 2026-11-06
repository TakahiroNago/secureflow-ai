<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Append-only (docs/database-design.md §3.6). A null scan_decision means not scanned, never allowed: only
 * rows from before step 2-3 can have one, and steps 2-5 and 2-6 refuse such a revision.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $workflow_id
 * @property int $revision_no
 * @property array<string, mixed> $plan_snapshot
 * @property string $plan_hash
 * @property int $hash_version
 * @property string $policy_version
 * @property string|null $scan_id
 * @property string|null $scan_decision
 * @property string $change_type
 * @property string|null $created_by
 * @property CarbonInterface $created_at
 * @property-read SecurityScan|null $scan
 */
class WorkflowRevision extends Model
{
    use BelongsToOrganization, HasUuids;

    public const UPDATED_AT = null;

    /**
     * @return BelongsTo<SecurityScan, $this>
     */
    public function scan(): BelongsTo
    {
        return $this->belongsTo(SecurityScan::class, 'scan_id');
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['plan_snapshot' => 'array', 'revision_no' => 'integer', 'hash_version' => 'integer'];
    }
}
