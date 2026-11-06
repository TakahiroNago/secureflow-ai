<?php

namespace App\Http\Resources;

use App\Models\AiAnalysisRequest;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * @mixin AiAnalysisRequest
 */
final class AnalysisResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'status' => $this->status,
            'workflow_id' => $this->workflow_id,
            'error_code' => $this->error_code,
            'scan' => ScanStatus::of(null),
        ];
    }
}
