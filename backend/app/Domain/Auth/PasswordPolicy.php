<?php

namespace App\Domain\Auth;

use Closure;

/**
 * docs/security-design.md §12: at least 12 characters, a length limit so that hashing cannot be
 * used for denial of service, and not on the common password list.
 */
final class PasswordPolicy
{
    public const MIN_LENGTH = 12;

    public const MAX_LENGTH = 1024;

    /**
     * @return list<mixed>
     */
    public static function rules(): array
    {
        return [
            'required',
            'string',
            'min:'.self::MIN_LENGTH,
            'max:'.self::MAX_LENGTH,
            function (string $attribute, mixed $value, Closure $fail): void {
                if (is_string($value) && CommonPasswordList::contains($value)) {
                    $fail('このパスワードは広く使われているため使用できません。');
                }
            },
        ];
    }
}
