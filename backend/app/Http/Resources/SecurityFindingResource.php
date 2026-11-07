<?php

namespace App\Http\Resources;

use App\Models\SecurityFinding;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * docs/api-design.md §3.7. The excerpt is the only text, and it came from masked text that is kept anyway. The scan
 * is included when it was loaded, so that the list says what each finding was found in.
 *
 * @mixin SecurityFinding
 */
final class SecurityFindingResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'category' => $this->category,
            'rule_id' => $this->rule_id,
            'severity' => $this->severity,
            'action' => $this->action,
            'message' => $this->message,
            'masked_excerpt' => $this->masked_excerpt,
            'field' => $this->field_path,
            'status' => $this->status,
            'status_note' => $this->status_note,
            'status_changed_by' => $this->whenLoaded('statusChangedBy', fn () => $this->statusChangedBy === null ? null : [
                'id' => $this->statusChangedBy->id,
                'name' => $this->statusChangedBy->name,
            ], null),
            'status_changed_at' => $this->status_changed_at?->toIso8601ZuluString(),
            'created_at' => $this->created_at->toIso8601ZuluString(),
            'scan' => $this->whenLoaded('scan', fn () => [
                'id' => $this->scan->id,
                'target_type' => $this->scan->target_type,
                'target_id' => $this->scan->target_id,
                'decision' => $this->scan->decision,
                'block_reason' => $this->scan->block_reason,
                'max_severity' => $this->scan->max_severity,
                'created_at' => $this->scan->created_at->toIso8601ZuluString(),
            ]),
        ];
    }
}
