<?php

namespace App\Http\Requests;

use App\Models\OrganizationSetting;
use App\Models\User;
use Closure;

/**
 * A text to be scanned. It is checked here and handed to the scanner, and an answer never repeats it.
 */
abstract class InputTextRequest extends StrictFormRequest
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

    public function inputText(): string
    {
        return $this->string('input')->toString();
    }

    private function maxChars(): int
    {
        /** @var User $user */
        $user = $this->user();

        return OrganizationSetting::query()->whereKey($user->organization_id)->value('max_input_chars') ?? self::DEFAULT_MAX_CHARS;
    }
}
