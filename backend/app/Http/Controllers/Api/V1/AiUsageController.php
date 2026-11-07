<?php

namespace App\Http\Controllers\Api\V1;

use App\Domain\Workflow\AiUsageLedger;
use App\Http\Controllers\Controller;
use App\Http\Requests\AiUsageSummaryRequest;
use App\Models\AiUsageLog;
use App\Models\User;
use Illuminate\Http\JsonResponse;

/**
 * docs/api-design.md §3.2. A member sees their own use, an admin or auditor the organization's. The cost is an estimate,
 * and the organization's budget is not shown to a member.
 */
final class AiUsageController extends Controller
{
    private const MEMBER_ROLE = 'member';

    private const MICROS_PER_DOLLAR = 1_000_000;

    public function summary(AiUsageSummaryRequest $request, AiUsageLedger $ledger): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();
        $own = $user->role === self::MEMBER_ROLE;
        $period = $request->string('period', 'month')->toString();
        $since = $period === 'day' ? now('UTC')->startOfDay() : now('UTC')->startOfMonth();

        $rows = fn () => AiUsageLog::query()
            ->where('created_at', '>=', $since)
            ->where('status', '!=', AiUsageLog::STATUS_BUDGET_BLOCKED)
            ->when($own, fn ($query) => $query->where('user_id', $user->id));

        $limits = $ledger->limitsOf($user->organization_id);
        $today = $ledger->requestsToday($user);
        $month = $ledger->tokensThisMonth();

        return response()->json(['data' => [
            'period' => $period,
            'requests' => $rows()->count(),
            'tokens' => [
                'input' => (int) $rows()->sum('prompt_tokens'),
                'output' => (int) $rows()->sum('completion_tokens'),
                'total' => (int) $rows()->sum('total_tokens'),
            ],
            'estimated_cost_usd' => (int) $rows()->sum('estimated_cost_micros') / self::MICROS_PER_DOLLAR,
            'limits' => [
                'user_daily_requests' => ['used' => $today, 'limit' => $limits['daily_requests'], 'ratio' => round($today / $limits['daily_requests'], 4)],
                'organization_monthly_tokens' => $own ? null : ['used' => $month, 'limit' => $limits['monthly_tokens'], 'ratio' => round($month / $limits['monthly_tokens'], 4)],
            ],
        ]]);
    }
}
