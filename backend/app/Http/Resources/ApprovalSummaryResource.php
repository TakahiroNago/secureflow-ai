<?php

namespace App\Http\Resources;

use App\Domain\Workflow\ApprovalEligibility;
use App\Models\User;
use App\Models\Workflow;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * @mixin Workflow
 */
final class ApprovalSummaryResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        /** @var User $viewer */
        $viewer = $request->user();
        $reason = ApprovalEligibility::cannotApproveReason($viewer, $this->resource, $this->currentRevision, $this->tasks);

        return [
            'workflow_id' => $this->id,
            'title' => $this->title,
            'revision_no' => $this->currentRevision?->revision_no,
            'max_severity' => $this->max_severity,
            'created_by' => ['id' => $this->creator->id, 'name' => $this->creator->name],
            'submitted_at' => $this->submitted_at?->toIso8601ZuluString(),
            'can_approve' => $reason === null,
            'cannot_approve_reason' => $reason,
        ];
    }
}
