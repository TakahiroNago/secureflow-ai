<?php

namespace App\Http\Requests;

use App\Models\OrganizationSetting;
use App\Models\User;
use Closure;

/**
 * The input is checked and then dropped: nothing stores it before masking exists (step 2-1).
 */
final class StoreAnalysisRequest extends StrictFormRequest
{
    private const DEFAULT_MAX_CHARS = 4000;

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'input' => ['required', 'string', function (string $attribute, mixed $value, Closure $fail): void {
                if (is_string($value) && mb_strlen($value, 'UTF-8') > $this->maxChars()) {
                    $fail('入力が長すぎます。');
                }
            }],
        ];
    }

    public function inputCharCount(): int
    {
        return mb_strlen($this->string('input')->toString(), 'UTF-8');
    }

    private function maxChars(): int
    {
        /** @var User $user */
        $user = $this->user();

        return OrganizationSetting::query()->whereKey($user->organization_id)->value('max_input_chars') ?? self::DEFAULT_MAX_CHARS;
    }
}
