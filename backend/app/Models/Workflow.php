<?php

namespace App\Models;

use App\Domain\Workflow\WorkflowStatus;
use App\Support\Organization\BelongsToOrganization;
use Carbon\CarbonInterface;
use Database\Factories\WorkflowFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * status, lock_version and current_revision_id change through WorkflowTransition and the workflow
 * services, never through request data.
 *
 * @property string $id
 * @property string $organization_id
 * @property string $created_by
 * @property string $title
 * @property string $source_input_masked
 * @property WorkflowStatus $status
 * @property string|null $current_revision_id
 * @property string|null $max_severity
 * @property int $lock_version
 * @property CarbonInterface|null $submitted_at
 */
#[Fillable(['title', 'source_input_masked'])]
class Workflow extends Model
{
    /** @use HasFactory<WorkflowFactory> */
    use BelongsToOrganization, HasFactory, HasUuids;

    /**
     * As in the database, so that a workflow just created can be transitioned without reading it again.
     *
     * @var array<string, mixed>
     */
    protected $attributes = ['lock_version' => 0];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => WorkflowStatus::class,
            'lock_version' => 'integer',
            'submitted_at' => 'datetime',
        ];
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    /**
     * @return BelongsTo<WorkflowRevision, $this>
     */
    public function currentRevision(): BelongsTo
    {
        return $this->belongsTo(WorkflowRevision::class, 'current_revision_id');
    }

    /**
     * @return HasMany<WorkflowRevision, $this>
     */
    public function revisions(): HasMany
    {
        return $this->hasMany(WorkflowRevision::class);
    }

    /**
     * @return HasMany<WorkflowTask, $this>
     */
    public function tasks(): HasMany
    {
        return $this->hasMany(WorkflowTask::class);
    }
}
