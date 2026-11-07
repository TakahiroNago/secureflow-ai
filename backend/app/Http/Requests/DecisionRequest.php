<?php

namespace App\Http\Requests;

use App\Security\Output\AiTaskSchema;
use Closure;

/**
 * What every decision says: exactly which plan the person was looking at.
 */
abstract class DecisionRequest extends StrictFormRequest
{
    private const TEXT_LIMIT = 1000;

    /**
     * @return array<string, mixed>
     */
    protected function planRules(): array
    {
        return [
            'revision_no' => ['required', function (string $attribute, mixed $value, Closure $fail): void {
                if (! is_int($value) || $value < 1) {
                    $fail('入力内容を確認してください。');
                }
            }],
            'plan_hash' => ['required', 'string', 'regex:/^[0-9a-f]{64}$/D'],
        ];
    }

    protected function textRule(): Closure
    {
        return function (string $attribute, mixed $value, Closure $fail): void {
            if (AiTaskSchema::textProblem($value, self::TEXT_LIMIT) !== null) {
                $fail('入力内容を確認してください。');
            }
        };
    }
}
