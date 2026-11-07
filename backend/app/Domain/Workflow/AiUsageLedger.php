<?php

namespace App\Domain\Workflow;

use App\Ai\AiFailure;
use App\Ai\AiPricing;
use App\Ai\AiResponse;
use App\Ai\AiTokens;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Models\AiUsageLog;
use App\Models\OrganizationSetting;
use App\Models\User;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Log;
use PDOException;

/**
 * What the AI has been used for, and whether it may be used again (docs/security-design.md §6). Checked when an analysis
 * is asked for, and again just before the call, since a job can wait. Requests at the same moment can pass together and
 * go a little over: the provider's own spend limit is what stops the money (R-30).
 */
final readonly class AiUsageLedger
{
    public const USER_DAILY_LIMIT = 'USER_DAILY_LIMIT';

    public const ORGANIZATION_MONTHLY_LIMIT = 'ORGANIZATION_MONTHLY_LIMIT';

    public function __construct(private AuditLogger $audit) {}

    /**
     * @return array{monthly_tokens: int, daily_requests: int}
     */
    public function limitsOf(string $organizationId): array
    {
        // An organization with no settings row still has limits: the model's defaults.
        $settings = OrganizationSetting::effectiveFor($organizationId);

        return [
            'monthly_tokens' => $settings['monthly_token_limit'],
            'daily_requests' => $settings['user_daily_request_limit'],
        ];
    }

    /**
     * The month and the day are in UTC, like every time in the API. A call that was refused here does not count.
     */
    public function refusalFor(User $user): ?string
    {
        $limits = $this->limitsOf($user->organization_id);

        if ($this->tokensThisMonth() >= $limits['monthly_tokens']) {
            return self::ORGANIZATION_MONTHLY_LIMIT;
        }

        return $this->requestsToday($user) >= $limits['daily_requests'] ? self::USER_DAILY_LIMIT : null;
    }

    public function tokensThisMonth(?User $only = null): int
    {
        return (int) AiUsageLog::query()
            ->where('created_at', '>=', now('UTC')->startOfMonth())
            ->when($only !== null, fn ($query) => $query->where('user_id', $only?->id))
            ->sum('total_tokens');
    }

    public function requestsToday(User $user): int
    {
        return AiUsageLog::query()
            ->where('user_id', $user->id)
            ->where('created_at', '>=', now('UTC')->startOfDay())
            ->where('status', '!=', AiUsageLog::STATUS_BUDGET_BLOCKED)
            ->count();
    }

    /**
     * A refusal is recorded, and the AI is not called.
     */
    public function recordRefusal(User $user, ?string $analysisId, string $reason): void
    {
        $this->write($user, $analysisId, AiUsageLog::STATUS_BUDGET_BLOCKED, null, null, null, $reason, null, null);

        $metadata = ['provider' => $this->provider(), 'reason_code' => $reason];
        $entry = $analysisId === null
            ? AuditEntry::byUser(AuditEventType::AiCall, $user, 'denied', $metadata)
            : AuditEntry::byUserOn(AuditEventType::AiCall, $user, 'ai_analysis', $analysisId, $metadata, 'denied');

        $this->audit->recordAfterTransaction($entry, 'ai_call_unrecorded');
    }

    public function recordSuccess(User $user, string $analysisId, AiResponse $response, int $latencyMs): void
    {
        $this->write($user, $analysisId, AiUsageLog::STATUS_SUCCESS, $response->tokens, $response->model, $response->requestId, null, $latencyMs, null);
        $this->recordCall($user, $analysisId, 'success', $response->tokens, $response->model, null);
    }

    public function recordFailure(User $user, string $analysisId, AiFailure $failure, ?AiTokens $tokens, int $latencyMs): void
    {
        $status = match (true) {
            $failure === AiFailure::Timeout => AiUsageLog::STATUS_TIMEOUT,
            $failure === AiFailure::RateLimited => AiUsageLog::STATUS_RATE_LIMITED,
            $failure->isInvalidOutput() => AiUsageLog::STATUS_INVALID_OUTPUT,
            default => AiUsageLog::STATUS_ERROR,
        };

        $this->write($user, $analysisId, $status, $tokens, $this->configuredModel(), null, $failure->value, $latencyMs, null);
        $this->recordCall($user, $analysisId, 'failure', $tokens, $this->configuredModel(), $failure->value);
    }

    private function recordCall(User $user, string $analysisId, string $result, ?AiTokens $tokens, ?string $model, ?string $reason): void
    {
        $this->audit->recordAfterTransaction(
            AuditEntry::byUserOn(AuditEventType::AiCall, $user, 'ai_analysis', $analysisId, array_filter([
                'provider' => $this->provider(),
                'model' => $model,
                'total_tokens' => $tokens?->total,
                'reason_code' => $reason,
            ], fn (string|int|null $value) => $value !== null), $result),
            'ai_call_unrecorded',
        );
    }

    /**
     * A row that cannot be written leaves the budget short, and the call has already been made, so it does not stop the
     * work: the log has it.
     */
    private function write(User $user, ?string $analysisId, string $status, ?AiTokens $tokens, ?string $model, ?string $requestId, ?string $error, ?int $latencyMs, ?int $cost): void
    {
        try {
            (new AiUsageLog)->forceFill([
                'user_id' => $user->id,
                'analysis_request_id' => $analysisId,
                'provider' => $this->provider(),
                'model' => $model,
                'purpose' => AiUsageLog::PURPOSE_TASK_GENERATION,
                'prompt_tokens' => $tokens?->input,
                'completion_tokens' => $tokens?->output,
                'total_tokens' => $tokens?->total,
                'estimated_cost_micros' => $cost ?? ($tokens !== null && $model !== null ? AiPricing::estimateMicros($model, $tokens) : null),
                'latency_ms' => $latencyMs,
                'status' => $status,
                'error_code' => $error,
                'provider_request_id' => $requestId,
            ])->save();
        } catch (QueryException|PDOException $exception) {
            Log::critical('ai.usage_not_recorded', ['metric' => 'ai.usage_not_recorded', 'status' => $status, 'tokens' => $tokens?->total, 'exception' => $exception::class]);
        }
    }

    private function provider(): string
    {
        return config()->string('ai.provider');
    }

    private function configuredModel(): ?string
    {
        return $this->provider() === 'openai' ? config()->string('ai.openai.model') : null;
    }
}
