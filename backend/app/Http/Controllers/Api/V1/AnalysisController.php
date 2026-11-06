<?php

namespace App\Http\Controllers\Api\V1;

use App\Domain\Workflow\AnalysisService;
use App\Http\Controllers\Controller;
use App\Http\Requests\StoreAnalysisRequest;
use App\Http\Resources\AnalysisResource;
use App\Models\AiAnalysisRequest;
use App\Models\User;
use Illuminate\Http\JsonResponse;

final class AnalysisController extends Controller
{
    public function store(StoreAnalysisRequest $request, AnalysisService $analyses): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        return AnalysisResource::accepted($analyses->request($user, $request->inputText()))
            ->response()
            ->setStatusCode(202);
    }

    public function show(AiAnalysisRequest $analysis): AnalysisResource
    {
        return new AnalysisResource($analysis);
    }
}
