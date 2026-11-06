<?php

namespace App\Http\Resources;

use App\Models\AiAnalysisRequest;
use App\Models\SecurityScan;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * @mixin AiAnalysisRequest
 */
final class AnalysisResource extends JsonResource
{
    private bool $showMaskedInput = false;

    /**
     * The answer to the request itself, the one time the person who sent it sees what was kept. Afterwards
     * the masked text is gone anyway (docs/database-design.md §6).
     */
    public static function accepted(AiAnalysisRequest $analysis): self
    {
        $resource = new self($analysis);
        $resource->showMaskedInput = true;

        return $resource;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        $scan = $this->input_scan_id === null ? null : SecurityScan::query()->with('findings')->find($this->input_scan_id);

        return [
            'id' => $this->id,
            'status' => $this->status,
            'workflow_id' => $this->workflow_id,
            'error_code' => $this->error_code,
            'scan' => ScanStatus::of($scan, $this->showMaskedInput ? $this->input_masked : null),
        ];
    }
}
