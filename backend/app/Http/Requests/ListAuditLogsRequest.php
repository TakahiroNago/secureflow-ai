<?php

namespace App\Http\Requests;

use App\Audit\AuditEventType;
use Illuminate\Validation\Rule;

/**
 * There is no chain_id here on purpose: the organization comes from the session (docs/api-design.md §3.8).
 */
final class ListAuditLogsRequest extends StrictFormRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'event_type' => ['sometimes', Rule::enum(AuditEventType::class)],
            'actor_user_id' => ['sometimes', 'uuid'],
            'result' => ['sometimes', Rule::in(['success', 'failure', 'denied'])],
            'severity' => ['sometimes', Rule::in(['low', 'medium', 'high', 'critical'])],
            'from' => ['sometimes', 'date'],
            'to' => ['sometimes', 'date'],
            'cursor' => ['sometimes', 'string', 'max:1000'],
            'limit' => ['sometimes', 'integer', 'min:1', 'max:100'],
        ];
    }
}
