<?php

namespace App\Domain\Dashboard;

use App\Domain\Workflow\WorkflowStatus;
use App\Models\AiAnalysisRequest;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowExecution;
use App\Support\Organization\OrganizationContext;
use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;

/**
 * docs/api-design.md §3.2. A member counts their own work, an admin or auditor the whole organization.
 *
 * What does not exist yet is null, never 0: "0 warnings" would read as "safe" when nothing has looked.
 * Counts of approvals and executions are real zeros, because those tables exist.
 */
final readonly class DashboardSummary
{
    /** The only events shown here. The audit log itself is for an admin or auditor (step 2-7). */
    public const RECENT_EVENTS = ['auth.login', 'auth.logout', 'workflow.created', 'workflow.updated'];

    private const RECENT_LIMIT = 10;

    private const MEMBER_ROLE = 'member';

    public function __construct(private OrganizationContext $context) {}

    /**
     * @return array<string, mixed>
     */
    public function for(User $user): array
    {
        $byStatus = $this->countsByStatus($user);

        return [
            'workflows' => [
                'total' => array_sum($byStatus),
                'by_status' => $byStatus,
            ],
            'executed' => $this->executed($user),
            'pending_approval' => $byStatus[WorkflowStatus::Pending->value],
            'analyses_this_month' => $this->analysesThisMonth($user),
            'security' => ['warnings' => null, 'findings' => null, 'available_from_step' => '2-3'],
            'ai_usage' => ['tokens' => null, 'estimated_cost' => null, 'available_from_step' => '2-8'],
            'self_test' => ['latest' => null, 'available_from_step' => '3-3'],
            'recent_operations' => $this->recentOperations($user),
        ];
    }

    /**
     * Every status appears, so that the chart keeps its shape while some are empty.
     *
     * @return array<string, int>
     */
    private function countsByStatus(User $user): array
    {
        /** @var array<string, int> $counts */
        $counts = $this->ownWorkflows($user)
            ->toBase()
            ->selectRaw('status, count(*) AS total')
            ->groupBy('status')
            ->pluck('total', 'status')
            ->map(fn ($total) => (int) $total)
            ->all();

        $all = [];
        foreach (WorkflowStatus::cases() as $status) {
            $all[$status->value] = $counts[$status->value] ?? 0;
        }

        return $all;
    }

    private function executed(User $user): int
    {
        return WorkflowExecution::query()
            ->where('status', 'completed')
            ->when($this->isMember($user), fn ($query) => $query->whereIn('workflow_id', Workflow::query()->where('created_by', $user->id)->select('id')))
            ->count();
    }

    /**
     * The month in UTC, like every time in the API (docs/api-design.md §1).
     */
    private function analysesThisMonth(User $user): int
    {
        return AiAnalysisRequest::query()
            ->where('created_at', '>=', now('UTC')->startOfMonth())
            ->when($this->isMember($user), fn ($query) => $query->where('user_id', $user->id))
            ->count();
    }

    /**
     * Who did what and when, and nothing else: no address, no metadata. The system chain has no
     * organization, so this condition cannot match it.
     *
     * @return array<int, array<string, mixed>>
     */
    private function recentOperations(User $user): array
    {
        $rows = DB::table('audit_logs')
            ->leftJoin('users', 'users.id', '=', 'audit_logs.actor_user_id')
            ->where('audit_logs.organization_id', $this->context->id())
            ->whereIn('audit_logs.event_type', self::RECENT_EVENTS)
            ->when($this->isMember($user), fn ($query) => $query->where('audit_logs.actor_user_id', $user->id))
            ->orderByDesc('audit_logs.occurred_at')
            ->orderByDesc('audit_logs.chain_seq')
            ->limit(self::RECENT_LIMIT)
            ->get(['audit_logs.event_id', 'audit_logs.event_type', 'audit_logs.actor_user_id', 'users.name AS actor_name', 'audit_logs.resource_type', 'audit_logs.resource_id', 'audit_logs.result', 'audit_logs.occurred_at']);

        return $rows->map(fn (object $row) => [
            'id' => $row->event_id,
            'event_type' => $row->event_type,
            'actor' => $row->actor_user_id === null ? null : ['id' => $row->actor_user_id, 'name' => $row->actor_name],
            'resource_type' => $row->resource_type,
            'resource_id' => $row->resource_id,
            'result' => $row->result,
            'occurred_at' => CarbonImmutable::parse($row->occurred_at)->utc()->toIso8601ZuluString(),
        ])->values()->all();
    }

    /**
     * @return Builder<Workflow>
     */
    private function ownWorkflows(User $user): Builder
    {
        return Workflow::query()->when($this->isMember($user), fn ($query) => $query->where('created_by', $user->id));
    }

    private function isMember(User $user): bool
    {
        return $user->role === self::MEMBER_ROLE;
    }
}
