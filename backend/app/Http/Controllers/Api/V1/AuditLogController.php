<?php

namespace App\Http\Controllers\Api\V1;

use App\Audit\AuditChainVerifier;
use App\Audit\VerificationFailureReporter;
use App\Http\Controllers\Controller;
use App\Http\Requests\ListAuditLogsRequest;
use App\Http\Resources\AuditLogResource;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

/**
 * docs/api-design.md §3.8. Only the caller's organization: the system chain cannot be read or verified from here.
 */
final class AuditLogController extends Controller
{
    private const PAGE_SIZE = 50;

    /**
     * In chain order, the only order the design relies on: occurred_at is not one (docs/database-design.md §3.12).
     */
    public function index(ListAuditLogsRequest $request): AnonymousResourceCollection
    {
        $logs = AuditLog::query()
            ->when($request->filled('event_type'), fn ($query) => $query->where('event_type', $request->string('event_type')->toString()))
            ->when($request->filled('actor_user_id'), fn ($query) => $query->where('actor_user_id', $request->string('actor_user_id')->toString()))
            ->when($request->filled('result'), fn ($query) => $query->where('result', $request->string('result')->toString()))
            ->when($request->filled('severity'), fn ($query) => $query->where('severity', $request->string('severity')->toString()))
            ->when($request->filled('from'), fn ($query) => $query->where('occurred_at', '>=', $request->date('from')))
            ->when($request->filled('to'), fn ($query) => $query->where('occurred_at', '<=', $request->date('to')))
            ->orderByDesc('chain_seq')
            ->cursorPaginate($request->integer('limit', self::PAGE_SIZE));

        AuditLogResource::$actorNames = User::query()
            ->whereIn('id', collect($logs->items())->pluck('actor_user_id')->filter()->unique()->values())
            ->pluck('name', 'id')
            ->all();

        return AuditLogResource::collection($logs);
    }

    /**
     * Finding a break is the answer, not a failure of this request. A saved head can only be compared by the command.
     */
    public function verify(Request $request, AuditChainVerifier $verifier, VerificationFailureReporter $reporter): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        $result = $verifier->verify($user->organization_id);

        if (! $result['valid']) {
            $reporter->report($result);
        }

        return response()->json(['data' => [
            'valid' => $result['valid'],
            'checked_count' => $result['checked_count'],
            'first_broken_seq' => $result['first_broken_seq'],
            'reason_code' => $result['reason_code'],
        ]]);
    }
}
