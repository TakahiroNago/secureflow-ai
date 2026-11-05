<?php

namespace App\Domain\Auth;

use Illuminate\Support\Facades\Redis;
use Redis as PhpRedis;

/**
 * The raw client on the session connection: no retries, so a stopped Redis answers within its timeout
 * and the request gets 503 like any other session failure.
 */
final class RedisRetiredSessions implements RetiredSessions
{
    public const CONNECTION = 'session';

    public static function key(string $sessionId): string
    {
        return 'session_retired:'.hash('sha256', $sessionId);
    }

    public function retire(string $sessionId): void
    {
        $this->client()->setex(self::key($sessionId), $this->ttl(), '1');
    }

    public function claim(string $sessionId): bool
    {
        return (bool) $this->client()->set(self::key($sessionId), '1', ['nx', 'ex' => $this->ttl()]);
    }

    public function restore(string $sessionId): void
    {
        $this->client()->del(self::key($sessionId));
    }

    public function isRetired(string $sessionId): bool
    {
        return (bool) $this->client()->exists(self::key($sessionId));
    }

    /**
     * @return PhpRedis
     */
    private function client(): mixed
    {
        return Redis::connection(self::CONNECTION)->client();
    }

    /**
     * Longer than the idle limit: a request still holding the session cannot outlive it by more than that.
     */
    private function ttl(): int
    {
        return config()->integer('session.lifetime') * 60 + config()->integer('audit.password_pending_ttl_margin_seconds');
    }
}
