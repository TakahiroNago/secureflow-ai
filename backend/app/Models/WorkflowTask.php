<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * The current working set (docs/database-design.md §3.7). Execution uses the approved snapshot, not this.
 * derived_permissions and policy_decision come from ActionCatalog, never from a client or the AI.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $workflow_id
 * @property int $position
 * @property string $title
 * @property string $description
 * @property string $action_type
 * @property list<string> $steps
 * @property string $priority
 * @property string $target_data
 * @property string $impact_summary
 * @property list<string> $derived_permissions
 * @property list<string> $ai_claimed_permissions
 * @property string $policy_decision
 */
class WorkflowTask extends Model
{
    use BelongsToOrganization, HasUuids;

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'position' => 'integer',
            'steps' => 'array',
            'derived_permissions' => 'array',
            'ai_claimed_permissions' => 'array',
        ];
    }
}
