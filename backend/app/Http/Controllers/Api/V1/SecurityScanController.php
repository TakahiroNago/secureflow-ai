<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Resources\ScanStatus;
use App\Http\Resources\SecurityFindingResource;
use App\Models\SecurityScan;
use Illuminate\Http\JsonResponse;

/**
 * docs/api-design.md §3.7. A scan holds no text, so there is nothing here that the findings list does not also
 * show; it is the one place to see all of a scan's findings with their statuses, and the notice, together.
 */
final class SecurityScanController extends Controller
{
    public function show(SecurityScan $scan): JsonResponse
    {
        $scan->load(['user', 'findings' => fn ($query) => $query->with('statusChangedBy')]);

        return response()->json(['data' => [
            'id' => $scan->id,
            'target_type' => $scan->target_type,
            'target_id' => $scan->target_id,
            'user' => $scan->user === null ? null : ['id' => $scan->user->id, 'name' => $scan->user->name],
            'ruleset_version' => $scan->ruleset_version,
            'duration_ms' => $scan->duration_ms,
            'created_at' => $scan->created_at->toIso8601ZuluString(),
            ...ScanStatus::of($scan),
            'findings' => SecurityFindingResource::collection($scan->findings)->resolve(),
        ]], 200, [], JSON_UNESCAPED_UNICODE);
    }
}
