<?php

namespace App\Domain\Auth;

/**
 * Session ids that must never be stored or sent again: ended by a logout, or replaced by a login or a
 * password change. Laravel does not lock sessions and writes one back at the end of every request, so
 * a request that read a session before it ended would otherwise bring it back, login included.
 *
 * An id is retired before its session is removed. Then a write either comes before the removal and is
 * removed with it, or comes after the retirement and is refused (docs/security-design.md §16.5.5).
 */
interface RetiredSessions
{
    public function retire(string $sessionId): void;

    /**
     * Retires the id only if nothing else has: the one right to replace this session.
     */
    public function claim(string $sessionId): bool;

    /**
     * The replacement could not be stored, so the id is in use after all.
     */
    public function restore(string $sessionId): void;

    public function isRetired(string $sessionId): bool;
}
