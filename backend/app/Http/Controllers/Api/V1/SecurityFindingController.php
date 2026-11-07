<?php

namespace App\Http\Controllers\Api\V1;

use App\Domain\Security\FindingStatusChanger;
use App\Http\Controllers\Controller;
use App\Http\Requests\ListFindingsRequest;
use App\Http\Requests\UpdateFindingStatusRequest;
use App\Http\Resources\SecurityFindingResource;
use App\Models\SecurityFinding;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

/**
 * docs/api-design.md §3.7. The policy on the route decides who may be here; the query decides what a member sees.
 */
final class SecurityFindingController extends Controller
{
    private const PAGE_SIZE = 50;

    private const ROLE_MEMBER = 'member';

    /**
     * Newest first. A member sees the findings of their own scans only (docs/api-design.md §2).
     */
    public function index(ListFindingsRequest $request): AnonymousResourceCollection
    {
        /** @var User $user */
        $user = $request->user();

        $findings = SecurityFinding::query()
            ->with(['scan', 'statusChangedBy'])
            ->when($user->role === self::ROLE_MEMBER, fn (Builder $query) => $query->whereHas('scan', fn (Builder $scan) => $scan->where('user_id', $user->id)))
            ->when($request->filled('severity'), fn (Builder $query) => $query->where('severity', $request->string('severity')->toString()))
            ->when($request->filled('status'), fn (Builder $query) => $query->where('status', $request->string('status')->toString()))
            ->when($request->filled('category'), fn (Builder $query) => $query->where('category', $request->string('category')->toString()))
            ->orderByDesc('created_at')
            ->orderByDesc('id')
            ->cursorPaginate($request->integer('limit', self::PAGE_SIZE));

        return SecurityFindingResource::collection($findings);
    }

    public function update(UpdateFindingStatusRequest $request, SecurityFinding $finding, FindingStatusChanger $changer): SecurityFindingResource
    {
        /** @var User $user */
        $user = $request->user();

        $changed = $changer->change($user, $finding, $request->status(), $request->note());

        return new SecurityFindingResource($changed->load(['scan', 'statusChangedBy']));
    }
}
