<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * One thing a scan found (docs/database-design.md §3.11). The message is a fixed sentence, and an excerpt
 * only ever comes from masked text that is being kept anyway.
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
 */
class SecurityFinding extends Model
{
    use BelongsToOrganization, HasUuids;

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['position_start' => 'integer', 'position_end' => 'integer'];
    }
}
