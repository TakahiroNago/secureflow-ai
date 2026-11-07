<?php

namespace App\Http\Requests;

use App\Models\OrganizationSetting;
use Closure;

/**
 * docs/api-design.md §3.9. Whole numbers only, as JSON numbers: "5" is not a limit. The ranges are those of the
 * database (docs/database-design.md §3.2), with an upper bound where the database has none.
 */
final class UpdateLimitsRequest extends StrictFormRequest
{
    /** @var array<string, array{int, int}> */
    public const RANGES = [
        'monthly_token_limit' => [1, 1_000_000_000],
        'user_daily_request_limit' => [1, 100_000],
        'max_input_chars' => [1, 20_000],
    ];

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        $rules = [];

        foreach (OrganizationSetting::LIMIT_FIELDS as $field) {
            [$min, $max] = self::RANGES[$field];
            $others = array_values(array_diff(OrganizationSetting::LIMIT_FIELDS, [$field]));

            $rules[$field] = ['required_without_all:'.implode(',', $others), function (string $attribute, mixed $value, Closure $fail) use ($min, $max): void {
                if (! is_int($value) || $value < $min || $value > $max) {
                    $fail('入力内容を確認してください。');
                }
            }];
        }

        return $rules;
    }

    /**
     * @return array<string, int>
     */
    public function changes(): array
    {
        $changes = [];

        foreach (OrganizationSetting::LIMIT_FIELDS as $field) {
            if ($this->has($field)) {
                $changes[$field] = $this->integer($field);
            }
        }

        return $changes;
    }
}
