<?php

namespace App\Http\Requests;

use App\Domain\Security\FindingStatus;
use Illuminate\Validation\Rule;

/**
 * docs/api-design.md §3.7. The organization and, for a member, the owner come from the session, never from here.
 */
final class ListFindingsRequest extends StrictFormRequest
{
    /** As the database constrains them (docs/database-design.md §3.11). */
    public const CATEGORIES = ['pii', 'secret', 'injection', 'schema', 'forbidden_action', 'permission_mismatch', 'markup', 'canary', 'masking'];

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'severity' => ['sometimes', Rule::in(['low', 'medium', 'high', 'critical'])],
            'status' => ['sometimes', Rule::enum(FindingStatus::class)],
            'category' => ['sometimes', Rule::in(self::CATEGORIES)],
            'cursor' => ['sometimes', 'string', 'max:1000'],
            'limit' => ['sometimes', 'integer', 'min:1', 'max:100'],
        ];
    }
}
