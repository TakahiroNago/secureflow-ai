<?php

namespace App\Http\Controllers\Api\V1;

use App\Domain\Workflow\AnalysisService;
use App\Http\Controllers\Controller;
use App\Http\Requests\ScanPreviewRequest;
use App\Http\Resources\ScanStatus;
use App\Models\User;
use Illuminate\Http\JsonResponse;

final class SecurityController extends Controller
{
    /**
     * A stop is an answer here, not an error: the question was what the scan would do (docs/api-design.md §3.3).
     */
    public function scanPreview(ScanPreviewRequest $request, AnalysisService $analyses): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        $result = $analyses->preview($user, $request->inputText());

        return response()->json(['data' => ScanStatus::ofResult($result, $result->blocks() ? null : $result->maskedText())]);
    }
}
