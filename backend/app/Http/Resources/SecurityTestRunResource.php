<?php

namespace App\Http\Resources;

use App\Models\SecurityTestResult;
use App\Models\SecurityTestRun;
use App\SelfTest\SelfTestCases;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * docs/api-design.md §3.7. The results come with the run when they were loaded (the detail), with the cases that
 * only CI can check, so that the screen never shows a passed run as the whole story.
 *
 * @mixin SecurityTestRun
 */
final class SecurityTestRunResource extends JsonResource
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'status' => $this->status,
            'total' => $this->total,
            'passed' => $this->passed,
            'failed' => $this->failed,
            'ruleset_version' => $this->ruleset_version,
            'policy_version' => $this->policy_version,
            'error_code' => $this->error_code,
            'triggered_by' => $this->whenLoaded('triggeredBy', fn () => $this->triggeredBy === null ? null : ['id' => $this->triggeredBy->id, 'name' => $this->triggeredBy->name], null),
            'created_at' => $this->created_at->toIso8601ZuluString(),
            'started_at' => $this->started_at?->toIso8601ZuluString(),
            'finished_at' => $this->finished_at?->toIso8601ZuluString(),
            'results' => $this->whenLoaded('results', fn () => $this->results
                ->sortBy('case_id')
                ->map(fn (SecurityTestResult $result) => [
                    'case_id' => $result->case_id,
                    'category' => $result->category,
                    'name' => $result->name,
                    'expected' => $result->expected,
                    'actual' => $result->actual,
                    'passed' => $result->passed,
                    'duration_ms' => $result->duration_ms,
                    'details' => (object) $result->details,
                ])
                ->values()
                ->all()),
            'ci_only_cases' => $this->when($this->relationLoaded('results'), fn () => collect(SelfTestCases::CI_ONLY)
                ->map(fn (string $name, string $id) => ['case_id' => $id, 'name' => $name])
                ->values()
                ->all()),
        ];
    }
}
