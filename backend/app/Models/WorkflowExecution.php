<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * docs/database-design.md §3.9. An approval is consumed by one execution, enforced by a unique constraint.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $workflow_id
 * @property string $approval_id
 * @property string $workflow_revision_id
 * @property string $idempotency_key
 * @property string $requested_by
 * @property string $status
 * @property CarbonInterface|null $started_at
 * @property CarbonInterface|null $heartbeat_at
 * @property CarbonInterface|null $finished_at
 * @property array<string, mixed>|null $result
 * @property string|null $error_code
 * @property CarbonInterface|null $created_at
 */
class WorkflowExecution extends Model
{
    use BelongsToOrganization, HasUuids;

    public const STATUS_QUEUED = 'queued';

    public const STATUS_RUNNING = 'running';

    public const STATUS_COMPLETED = 'completed';

    public const STATUS_FAILED = 'failed';

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'started_at' => 'datetime',
            'heartbeat_at' => 'datetime',
            'finished_at' => 'datetime',
            'result' => 'array',
        ];
    }
}
