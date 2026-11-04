<?php

namespace App\Domain\Auth;

use RuntimeException;

/**
 * The bundled common password list (docs/security-design.md §12.1). Local only: passwords are
 * never sent to an external service.
 */
final class CommonPasswordList
{
    public const SHA256 = '2ce4934bf860d3d348a9f4ea646df42e8e65c292c734f0633635148c53a73e86';

    public static function path(): string
    {
        return resource_path('security/common-passwords.txt');
    }

    /**
     * The list is lowercase, so the comparison ignores case. A missing list is an error, so a
     * deployment problem cannot silently disable the check.
     */
    public static function contains(string $password): bool
    {
        $entries = file(self::path(), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if ($entries === false || $entries === []) {
            throw new RuntimeException('The common password list is not available.');
        }

        return in_array(strtolower($password), $entries, true);
    }
}
