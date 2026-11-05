<?php

namespace Tests\Support;

use RedisException;
use SensitiveParameter;
use SessionHandlerInterface;

/**
 * Sessions can be read but not written while $failing is set, and writing fails the way it does when
 * Redis stops: with an exception. The session code runs for real.
 */
final class FailingWriteSessionHandler implements SessionHandlerInterface
{
    public bool $failing = true;

    public function __construct(private readonly SessionHandlerInterface $inner) {}

    public function open(string $path, string $name): bool
    {
        return $this->inner->open($path, $name);
    }

    public function close(): bool
    {
        return $this->inner->close();
    }

    public function read(string $id): string|false
    {
        return $this->inner->read($id);
    }

    public function write(string $id, #[SensitiveParameter] string $data): bool
    {
        if ($this->failing) {
            throw new RedisException('Connection lost');
        }

        return $this->inner->write($id, $data);
    }

    public function destroy(string $id): bool
    {
        return $this->inner->destroy($id);
    }

    public function gc(int $max_lifetime): int|false
    {
        return $this->inner->gc($max_lifetime);
    }
}
