<?php

namespace App\Audit;

use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Turns repeated failures into started, continuing and recovered log lines, so an outage does not
 * write one critical line per request. State is a local file, because Redis may be what is down.
 *
 * The state belongs to one container and affects only logging, never a response or a decision
 * (docs/security-design.md §16.5.7). Counts are approximate: a request that cannot take the lock is
 * not counted rather than made to wait.
 */
class OutageLog
{
    private const VERSION = 1;

    /** @var array<string, int> Per-process limit used when the state file cannot be used. */
    private static array $degradedLastLogged = [];

    /**
     * @param  array<string, string|int|null>  $context
     */
    public function failure(string $subject, string $cause, array $context = []): void
    {
        $interval = $this->interval();

        $done = $this->withState($subject, function (?array $state) use ($subject, $cause, $context, $interval): array {
            $now = now()->getTimestamp();

            if ($state === null || $now - $state['last_seen_at'] > 2 * $interval) {
                // Bouncing between failing and recovered: one "started" per interval, the rest counted.
                if ($this->recentFlaps($subject) === null) {
                    $this->emit($subject.'.outage_started', $context + ['cause' => $cause, 'started_at' => $now]);
                }

                return ['version' => self::VERSION, 'started_at' => $now, 'last_seen_at' => $now, 'last_logged_at' => $now, 'cause' => $cause, 'suppressed' => 0, 'total' => 1];
            }

            $state['total']++;
            $state['last_seen_at'] = $now;

            if ($state['cause'] !== $cause || $now - $state['last_logged_at'] >= $interval) {
                $this->emit($subject.'.outage_continuing', $context + [
                    'cause' => $cause,
                    'started_at' => $state['started_at'],
                    'duration_seconds' => $now - $state['started_at'],
                    'suppressed_count' => $state['suppressed'],
                    'flap_count' => $this->recentFlaps($subject) ?? 0,
                ]);
                $state['cause'] = $cause;
                $state['suppressed'] = 0;
                $state['last_logged_at'] = $now;
            } else {
                $state['suppressed']++;
            }

            return $state;
        });

        if (! $done) {
            $this->degraded($subject.'.outage_continuing', $context + ['cause' => $cause]);
        }
    }

    /**
     * @param  array<string, string|int|null>  $context
     */
    public function recovered(string $subject, array $context = []): void
    {
        $file = $this->stateFile($subject);

        if (! is_file($file)) {
            return;
        }

        $this->withState($subject, function (?array $state) use ($subject, $context): ?array {
            if ($state !== null) {
                $now = now()->getTimestamp();
                $flaps = $this->recentFlaps($subject);

                if ($flaps === null) {
                    $this->emit($subject.'.outage_recovered', $context + [
                        'started_at' => $state['started_at'],
                        'duration_seconds' => $now - $state['started_at'],
                        'total_count' => $state['total'],
                    ]);
                }

                @file_put_contents($this->flapFile($subject), (string) json_encode([
                    'at' => $flaps === null ? $now : $this->flapStartedAt($subject),
                    'count' => ($flaps ?? 0) + 1,
                ]));
            }

            return null;
        });
    }

    public function directory(): string
    {
        $configured = config('audit.log_state_directory');

        return is_string($configured) && $configured !== '' ? $configured : sys_get_temp_dir().'/secureflow-log-state';
    }

    private function recentFlaps(string $subject): ?int
    {
        $flap = json_decode((string) @file_get_contents($this->flapFile($subject)), true);

        if (! is_array($flap) || ! is_int($flap['at'] ?? null) || ! is_int($flap['count'] ?? null)) {
            return null;
        }

        return now()->getTimestamp() - $flap['at'] < $this->interval() ? $flap['count'] : null;
    }

    private function flapStartedAt(string $subject): int
    {
        $flap = json_decode((string) @file_get_contents($this->flapFile($subject)), true);

        return is_array($flap) && is_int($flap['at'] ?? null) ? $flap['at'] : now()->getTimestamp();
    }

    private function flapFile(string $subject): string
    {
        return $this->directory().'/'.$subject.'.flap';
    }

    /**
     * A repeated failure that is not an outage: one line per interval, with the count since the last.
     *
     * @param  array<string, string|int|null>  $context
     */
    public function occurrence(string $metric, string $key, array $context = []): void
    {
        $interval = $this->interval();

        $done = $this->withState('occurrence.'.md5($key), function (?array $state) use ($metric, $context, $interval): array {
            $now = now()->getTimestamp();

            if ($state === null || $now - $state['last_logged_at'] >= $interval) {
                $this->emit($metric, $context + ['suppressed_count' => $state['suppressed'] ?? 0]);

                return ['version' => self::VERSION, 'started_at' => $now, 'last_seen_at' => $now, 'last_logged_at' => $now, 'cause' => '', 'suppressed' => 0, 'total' => 1];
            }

            $state['suppressed']++;
            $state['last_seen_at'] = $now;

            return $state;
        });

        if (! $done) {
            $this->degraded($metric, $context);
        }
    }

    /**
     * @param  callable(?array{version: int, started_at: int, last_seen_at: int, last_logged_at: int, cause: string, suppressed: int, total: int}): ?array{version: int, started_at: int, last_seen_at: int, last_logged_at: int, cause: string, suppressed: int, total: int}  $change
     */
    private function withState(string $subject, callable $change): bool
    {
        try {
            $directory = $this->directory();
            if (! is_dir($directory) && ! @mkdir($directory, 0700, true) && ! is_dir($directory)) {
                return false;
            }

            // The kernel releases the lock if this process dies, so a crash cannot block the next one.
            $lock = @fopen($directory.'/'.$subject.'.lock', 'c');
            if ($lock === false) {
                return false;
            }

            try {
                if (! flock($lock, LOCK_EX | LOCK_NB)) {
                    return true;
                }

                $file = $this->stateFile($subject);
                $next = $change($this->read($file));

                if ($next === null) {
                    if (is_file($file)) {
                        @unlink($file);
                    }

                    return true;
                }

                // A rename leaves the old or the new content, never half of it.
                $temporary = $file.'.'.getmypid().'.tmp';
                if (@file_put_contents($temporary, json_encode($next, JSON_THROW_ON_ERROR)) === false) {
                    return false;
                }
                @chmod($temporary, 0600);

                return @rename($temporary, $file);
            } finally {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @return ?array{version: int, started_at: int, last_seen_at: int, last_logged_at: int, cause: string, suppressed: int, total: int}
     */
    private function read(string $file): ?array
    {
        if (! is_file($file)) {
            return null;
        }

        $state = json_decode((string) @file_get_contents($file), true);

        if (! is_array($state)
            || ($state['version'] ?? null) !== self::VERSION
            || ! is_int($state['started_at'] ?? null)
            || ! is_int($state['last_seen_at'] ?? null)
            || ! is_int($state['last_logged_at'] ?? null)
            || ! is_string($state['cause'] ?? null)
            || ! is_int($state['suppressed'] ?? null)
            || ! is_int($state['total'] ?? null)) {
            Log::critical('outage_log.state_reset', ['metric' => 'outage_log.state_reset', 'state_reset' => true]);

            return null;
        }

        /** @var array{version: int, started_at: int, last_seen_at: int, last_logged_at: int, cause: string, suppressed: int, total: int} $state */
        return $state;
    }

    /**
     * @param  array<string, string|int|null>  $context
     */
    private function emit(string $metric, array $context): void
    {
        Log::critical($metric, ['metric' => $metric, 'instance' => (string) gethostname()] + $context);
    }

    /**
     * @param  array<string, string|int|null>  $context
     */
    private function degraded(string $metric, array $context): void
    {
        $now = now()->getTimestamp();

        if ($now - (self::$degradedLastLogged[$metric] ?? 0) >= $this->interval()) {
            self::$degradedLastLogged[$metric] = $now;
            $this->emit($metric, $context + ['aggregation' => 'degraded']);
        }
    }

    private function interval(): int
    {
        return config()->integer('audit.log_aggregation_interval_seconds');
    }

    private function stateFile(string $subject): string
    {
        return $this->directory().'/'.$subject.'.json';
    }
}
