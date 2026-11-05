<?php

namespace App\Domain\Auth;

final readonly class PasswordChangeResult
{
    public const CHANGED = 'changed';

    public const CURRENT_INVALID = 'current_invalid';

    public const SAME_AS_CURRENT = 'same_as_current';

    public const KEY_CONFLICT = 'key_conflict';

    private function __construct(
        public string $status,
        public ?string $changedAt = null,
        public ?string $passwordHash = null,
        public bool $replayed = false,
    ) {}

    public static function changed(string $changedAt, string $passwordHash): self
    {
        return new self(self::CHANGED, $changedAt, $passwordHash);
    }

    /** Found already committed by another request. This request wrote no fingerprint of its own. */
    public static function replayed(string $changedAt, string $passwordHash): self
    {
        return new self(self::CHANGED, $changedAt, $passwordHash, true);
    }

    public static function of(string $status): self
    {
        return new self($status);
    }
}
