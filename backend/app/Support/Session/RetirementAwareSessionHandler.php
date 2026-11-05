<?php

namespace App\Support\Session;

use App\Domain\Auth\RedisRetiredSessions;
use Illuminate\Cache\RedisStore;
use Illuminate\Session\CacheBasedSessionHandler;
use Redis as PhpRedis;
use SensitiveParameter;

/**
 * Laravel's Redis session handler, with one change: the write and the check for a retired id are one
 * atomic step in Redis. A check in PHP would leave a moment between it and the write, in which a logout
 * could finish and the write would bring the session back.
 */
final class RetirementAwareSessionHandler extends CacheBasedSessionHandler
{
    private const WRITE_UNLESS_RETIRED = <<<'LUA'
        if redis.call('exists', KEYS[2]) == 1 then return 0 end
        redis.call('setex', KEYS[1], ARGV[1], ARGV[2])
        return 1
        LUA;

    /**
     * @param  string  $sessionId
     * @param  string  $data
     */
    public function write($sessionId, #[SensitiveParameter] $data): bool
    {
        /** @var RedisStore $store */
        $store = $this->cache->getStore();

        /** @var PhpRedis $client */
        $client = $store->connection()->client();

        // RedisStore::put() stores it serialized, and read() goes through RedisStore::get().
        return (bool) $client->eval(
            self::WRITE_UNLESS_RETIRED,
            [$store->getPrefix().$sessionId, RedisRetiredSessions::key($sessionId), max(1, $this->minutes * 60), serialize($data)],
            2,
        );
    }
}
