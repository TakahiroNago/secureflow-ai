<?php

namespace App\Models;

use App\Support\Organization\BelongsToOrganization;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * One run of the in-app security self-test (docs/database-design.md §3.14). Its counts and status change while it
 * runs; its results do not.
 *
 * @property string $id
 * @property string $organization_id
 * @property string|null $triggered_by
 * @property string $status
 * @property int $total
 * @property int $passed
 * @property int $failed
 * @property string|null $ruleset_version
 * @property string|null $policy_version
 * @property string|null $error_code
 * @property CarbonInterface|null $started_at
 * @property CarbonInterface|null $heartbeat_at
 * @property CarbonInterface|null $finished_at
 * @property CarbonInterface $created_at
 * @property CarbonInterface $updated_at
 * @property-read Collection<int, SecurityTestResult> $results
 * @property-read User|null $triggeredBy
 */
class SecurityTestRun extends Model
{
    use BelongsToOrganization, HasUuids;

    public const STATUS_QUEUED = 'queued';

    public const STATUS_RUNNING = 'running';

    public const STATUS_COMPLETED = 'completed';

    public const STATUS_FAILED = 'failed';

    /** @var list<string> */
    public const ACTIVE_STATUSES = [self::STATUS_QUEUED, self::STATUS_RUNNING];

    /**
     * @return HasMany<SecurityTestResult, $this>
     */
    public function results(): HasMany
    {
        return $this->hasMany(SecurityTestResult::class, 'run_id');
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function triggeredBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'triggered_by');
    }

    public function isFinished(): bool
    {
        return in_array($this->status, [self::STATUS_COMPLETED, self::STATUS_FAILED], true);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'total' => 'integer',
            'passed' => 'integer',
            'failed' => 'integer',
            'started_at' => 'datetime',
            'heartbeat_at' => 'datetime',
            'finished_at' => 'datetime',
        ];
    }
}
