<?php

namespace App\Domain\Auth;

use App\Support\Http\ServiceUnavailableException;
use Illuminate\Support\Facades\Redis;
use Redis as PhpRedis;
use RedisException;

/**
 * Keeps the row lock short: the conditions in docs/security-design.md §16.5.5 were measured, and each
 * one matters.
 *
 * - The raw client, never Connection::command(): on a lost connection that rebuilds the client and
 *   waited 5s on DNS, even with max_retries = 0.
 * - The connection checked with PING in prepare() is the one written to. No DNS, connect or reconnect
 *   happens under the lock.
 * - read_timeout alone does not bound the whole operation, so the elapsed time is measured with a
 *   monotonic clock, and an overrun fails even if the write succeeded. A write that timed out can
 *   still be applied later. That is harmless, see PendingFingerprintStore.
 */
final class RedisPendingFingerprintStore implements PendingFingerprintStore
{
    private const CONNECTION = 'pending';

    private ?PhpRedis $client = null;

    public function prepare(): void
    {
        try {
            $client = Redis::connection(self::CONNECTION)->client();

            if (! $client instanceof PhpRedis) {
                throw new RedisException('Expected the phpredis client.');
            }

            $client->ping();
            $this->client = $client;
        } catch (RedisException $exception) {
            throw new ServiceUnavailableException('The pending fingerprint store is not available.', 0, $exception);
        }
    }

    public function write(string $sessionId, string $fingerprint, string $owner): void
    {
        if ($this->client === null) {
            throw new ServiceUnavailableException('prepare() must run before the row lock.');
        }

        $start = hrtime(true);

        try {
            $this->client->setex($this->key($sessionId), $this->ttl(), (string) json_encode([
                'fingerprint' => $fingerprint,
                'owner' => $owner,
                'until' => now()->getTimestamp() + self::OWNER_SECONDS,
            ]));
        } catch (RedisException $exception) {
            throw new ServiceUnavailableException('The pending fingerprint could not be written.', 0, $exception);
        }

        $elapsedMs = (hrtime(true) - $start) / 1_000_000;

        if ($elapsedMs > config()->integer('audit.password_pending_redis_timeout_ms')) {
            throw new ServiceUnavailableException('The pending fingerprint took too long to write.');
        }
    }

    public function read(string $sessionId): ?string
    {
        $fingerprint = $this->entry($sessionId)['fingerprint'] ?? null;

        return is_string($fingerprint) ? $fingerprint : null;
    }

    public function mayRotate(string $sessionId, ?string $owner): bool
    {
        $entry = $this->entry($sessionId);

        return ! (is_string($entry['owner'] ?? null) && $entry['owner'] !== $owner && ($entry['until'] ?? 0) > now()->getTimestamp());
    }

    public function giveUpOwnership(string $sessionId): void
    {
        $entry = $this->entry($sessionId);

        if (is_string($entry['fingerprint'] ?? null)) {
            $this->client()->setex($this->key($sessionId), $this->ttl(), (string) json_encode(['fingerprint' => $entry['fingerprint']]));
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function entry(string $sessionId): array
    {
        $value = $this->client()->get($this->key($sessionId));
        $entry = is_string($value) ? json_decode($value, true) : null;

        return is_array($entry) ? $entry : [];
    }

    /**
     * Calls with the phpredis signature. Connection::command() would rebuild the client on a failure.
     *
     * @return PhpRedis
     */
    private function client(): mixed
    {
        return Redis::connection(self::CONNECTION)->client();
    }

    private function key(string $sessionId): string
    {
        return 'password_pending:'.hash('sha256', $sessionId);
    }

    /**
     * Longer than the session's idle limit. If it still expires first, the session simply stops
     * matching and the user logs in again.
     */
    private function ttl(): int
    {
        return config()->integer('session.lifetime') * 60 + config()->integer('audit.password_pending_ttl_margin_seconds');
    }
}
