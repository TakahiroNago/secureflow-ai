<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * The state of an analysis lives here, not in the queue (docs/architecture.md §10). A row in failed_jobs
 * does not say that the work failed, and this row does.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $user_id
 * @property string $status
 * @property string|null $input_masked
 * @property int $input_char_count
 * @property string|null $workflow_id
 * @property string|null $error_code
 * @property CarbonInterface|null $started_at
 * @property CarbonInterface|null $heartbeat_at
 * @property CarbonInterface|null $finished_at
 * @property CarbonInterface $created_at
 */
class AiAnalysisRequest extends Model
{
    use BelongsToOrganization, HasUuids;

    public const STATUS_QUEUED = 'queued';

    public const STATUS_PROCESSING = 'processing';

    public const STATUS_SUCCEEDED = 'succeeded';

    public const STATUS_FAILED = 'failed';

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'input_char_count' => 'integer',
            'started_at' => 'datetime',
            'heartbeat_at' => 'datetime',
            'finished_at' => 'datetime',
        ];
    }
}
