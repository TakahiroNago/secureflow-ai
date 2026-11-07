<?php

namespace App\Http\Requests;

use Closure;

final class ApproveWorkflowRequest extends DecisionRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            ...$this->planRules(),
            // Only true or false: "1" must not count as having confirmed a risk.
            'acknowledged_risks' => ['required', function (string $attribute, mixed $value, Closure $fail): void {
                if (! is_bool($value)) {
                    $fail('入力内容を確認してください。');
                }
            }],
            'comment' => ['nullable', 'string', $this->textRule()],
        ];
    }
}
