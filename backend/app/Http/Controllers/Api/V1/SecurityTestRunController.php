<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\ListTestRunsRequest;
use App\Http\Resources\SecurityTestRunResource;
use App\Models\SecurityTestRun;
use App\Models\User;
use App\SelfTest\SelfTestRuns;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

/**
 * docs/api-design.md §3.7. The policy on the route decides who may be here.
 */
final class SecurityTestRunController extends Controller
{
    private const PAGE_SIZE = 20;

    public function store(Request $request, SelfTestRuns $runs): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        $run = $runs->start($user);

        return (new SecurityTestRunResource($run->load('triggeredBy')))->response()->setStatusCode(202);
    }

    public function index(ListTestRunsRequest $request): AnonymousResourceCollection
    {
        $runs = SecurityTestRun::query()
            ->with('triggeredBy')
            ->orderByDesc('created_at')
            ->orderByDesc('id')
            ->cursorPaginate($request->integer('limit', self::PAGE_SIZE));

        return SecurityTestRunResource::collection($runs);
    }

    public function show(SecurityTestRun $run): SecurityTestRunResource
    {
        return new SecurityTestRunResource($run->load(['triggeredBy', 'results']));
    }
}
