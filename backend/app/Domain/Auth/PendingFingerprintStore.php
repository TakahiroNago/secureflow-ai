<?php

namespace App\Domain\Auth;

use App\Support\Http\ServiceUnavailableException;

/**
 * Where a password change keeps the fingerprint of the hash it is about to commit, written before
 * the commit so that the current session survives Redis stopping right after it.
 *
 * It decides nothing about the change itself: the database does. A leftover value is harmless,
 * because it only counts when it matches the committed hash (docs/security-design.md §16.5.5).
 */
interface PendingFingerprintStore
{
    /**
     * How long the request that wrote a fingerprint keeps the first right to rotate the session. Long
     * enough to cover its commit, and short, because a request that died must not block the session.
     */
    public const OWNER_SECONDS = 15;

    /**
     * Before the row lock: connect and check the connection. Failing here holds no lock.
     *
     * @throws ServiceUnavailableException
     */
    public function prepare(): void;

    /**
     * Under the row lock, on the connection from prepare().
     *
     * @throws ServiceUnavailableException when it failed or took too long, even if the write succeeded
     */
    public function write(string $sessionId, string $fingerprint, string $owner): void;

    public function read(string $sessionId): ?string;

    /**
     * False while another request's write is still its own to finish. The first request to commit is
     * the one that replaces the session, unless it died.
     */
    public function mayRotate(string $sessionId, ?string $owner): bool;

    /**
     * The new id could not be stored: a later request may finish instead.
     */
    public function giveUpOwnership(string $sessionId): void;
}
