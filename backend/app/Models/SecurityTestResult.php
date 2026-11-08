<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * What one case of a self-test found (docs/database-design.md §3.14). Never changed. The details hold fixed keys
 * and codes only: no text from a user or the AI.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $run_id
 * @property string $case_id
 * @property string $category
 * @property string $name
 * @property string $expected
 * @property string $actual
 * @property bool $passed
 * @property int $duration_ms
 * @property array<string, mixed> $details
 * @property CarbonInterface $created_at
 */
class SecurityTestResult extends Model
{
    use BelongsToOrganization, HasUuids;

    public const UPDATED_AT = null;

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['passed' => 'boolean', 'duration_ms' => 'integer', 'details' => 'array'];
    }
}
