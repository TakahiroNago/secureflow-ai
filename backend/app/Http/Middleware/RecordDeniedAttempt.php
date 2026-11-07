<?php

namespace App\Http\Middleware;

use App\Audit\AuditEventType;
use App\Domain\Workflow\DeniedAttempts;
use App\Models\User;
use App\Models\Workflow;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\Response;

/**
 * Sits just before the policy on the decision and execution routes, and records what the policy is about to refuse. It
 * refuses nothing itself. A 404 is not recorded: nothing about that workflow is the caller's to know, or to fill a chain with.
 */
final readonly class RecordDeniedAttempt
{
    private const NOT_FOUND = 404;

    public function __construct(private DeniedAttempts $denials) {}

    public function handle(Request $request, Closure $next, string $ability): Response
    {
        $user = $request->user();
        $workflow = $request->route('workflow');

        if ($user instanceof User && $workflow instanceof Workflow) {
            $refusal = Gate::forUser($user)->inspect($ability, $workflow);

            if ($refusal->denied() && $refusal->status() !== self::NOT_FOUND) {
                $type = $ability === 'execute' ? AuditEventType::ExecutionDenied : AuditEventType::ApprovalDenied;
                $this->denials->record($type, $user, $workflow, (string) ($refusal->code() ?? 'FORBIDDEN'));
            }
        }

        return $next($request);
    }
}
