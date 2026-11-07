<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * Append-only (docs/database-design.md §3.13). No prompt and no answer: this is what a call cost and how it ended.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $user_id
 * @property string|null $analysis_request_id
 * @property string $provider
 * @property string|null $model
 * @property string $purpose
 * @property int|null $prompt_tokens
 * @property int|null $completion_tokens
 * @property int|null $total_tokens
 * @property int|null $estimated_cost_micros
 * @property int|null $latency_ms
 * @property string $status
 * @property string|null $error_code
 * @property string|null $provider_request_id
 * @property CarbonInterface $created_at
 */
class AiUsageLog extends Model
{
    use BelongsToOrganization, HasUuids;

    public const UPDATED_AT = null;

    public const PURPOSE_TASK_GENERATION = 'task_generation';

    public const STATUS_SUCCESS = 'success';

    public const STATUS_ERROR = 'error';

    public const STATUS_TIMEOUT = 'timeout';

    public const STATUS_RATE_LIMITED = 'rate_limited';

    public const STATUS_BUDGET_BLOCKED = 'budget_blocked';

    public const STATUS_INVALID_OUTPUT = 'invalid_output';
}
