<?php

namespace App\Http\Requests;

use App\Security\Output\AiTaskSchema;
use App\Security\Policy\ActionCatalog;
use Closure;
use Illuminate\Validation\Rule;

/**
 * docs/api-design.md §3.4. These are all the fields a client can set. derived_permissions and
 * policy_decision are not among them, so sending them is an unknown field, and an error.
 * The same limits as for what the AI writes. A forbidden action is accepted and marked: it cannot be submitted.
 */
final class TaskRequest extends StrictFormRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        $rules = [
            'action_type' => ['required', 'string', Rule::in(ActionCatalog::types())],
            'priority' => ['required', 'string', Rule::in(AiTaskSchema::PRIORITIES)],
            'steps' => ['required', 'list', 'min:'.AiTaskSchema::MIN_STEPS, 'max:'.AiTaskSchema::MAX_STEPS],
            'steps.*' => ['required', 'string', self::text(AiTaskSchema::STEP_LIMIT)],
        ];

        foreach (AiTaskSchema::TEXT_LIMITS as $field => $limit) {
            $rules[$field] = ['required', 'string', self::text($limit)];
        }

        return $rules;
    }

    private static function text(int $limit): Closure
    {
        return function (string $attribute, mixed $value, Closure $fail) use ($limit): void {
            if (AiTaskSchema::textProblem($value, $limit) !== null) {
                $fail('入力内容を確認してください。');
            }
        };
    }
}
