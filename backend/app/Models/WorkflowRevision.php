<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * Append-only (docs/database-design.md §3.6). A null scan_decision means not scanned, never allowed:
 * security_scans arrives in step 2-3, and steps 2-5 and 2-6 refuse such a revision.
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
 */
class WorkflowRevision extends Model
{
    use BelongsToOrganization, HasUuids;

    public const UPDATED_AT = null;

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['plan_snapshot' => 'array', 'revision_no' => 'integer', 'hash_version' => 'integer'];
    }
}
