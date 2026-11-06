<?php

namespace App\Http\Requests;

use App\Security\Output\AiTaskSchema;
use Closure;

final class UpdateWorkflowRequest extends StrictFormRequest
{
    private const TITLE_LIMIT = 200;

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'title' => ['required', 'string', function (string $attribute, mixed $value, Closure $fail): void {
                if (AiTaskSchema::textProblem($value, self::TITLE_LIMIT) !== null) {
                    $fail('入力内容を確認してください。');
                }
            }],
        ];
    }
}
