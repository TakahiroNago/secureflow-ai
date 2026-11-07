<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Append-only (docs/database-design.md §3.8). Whether an approval is still valid is calculated, never stored.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $workflow_id
 * @property string $workflow_revision_id
 * @property string $plan_hash
 * @property string $decision
 * @property string $decided_by
 * @property string|null $comment
 * @property bool $acknowledged_risks
 * @property CarbonInterface $created_at
 * @property-read User $decider
 */
class Approval extends Model
{
    use BelongsToOrganization, HasUuids;

    public const UPDATED_AT = null;

    public const APPROVED = 'approved';

    public const REJECTED = 'rejected';

    /**
     * @return BelongsTo<User, $this>
     */
    public function decider(): BelongsTo
    {
        return $this->belongsTo(User::class, 'decided_by');
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['acknowledged_risks' => 'boolean'];
    }
}
