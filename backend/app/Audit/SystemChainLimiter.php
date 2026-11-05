<?php

namespace App\Audit;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * Caps anonymous events on the system chain, which can be written without authentication
 * (docs/security-design.md §16.5.4). Detection does not depend on the chain: the first excess in a
 * window is logged at once, and the total is logged before the chain is written.
 */
class SystemChainLimiter
{
    private const WINDOW_SECONDS = 60;

    private const KEEP_SECONDS = 86400;

    public function allow(): bool
    {
        $window = $this->window();
        $countKey = 'audit:system_chain:count:'.$window;

        Cache::add($countKey, 0, self::WINDOW_SECONDS * 2);
        $count = (int) Cache::increment($countKey);

        if ($count <= config()->integer('audit.system_chain_limit_per_minute')) {
            return true;
        }

        $suppressedKey = 'audit:system_chain:suppressed:'.$window;
        Cache::add($suppressedKey, 0, self::KEEP_SECONDS);

        if ((int) Cache::increment($suppressedKey) === 1) {
            Log::critical('audit.system_chain.suppressed', [
                'metric' => 'audit.system_chain.suppressed',
                'window_started_at' => $this->iso($window),
                'limit' => config()->integer('audit.system_chain_limit_per_minute'),
            ]);
            $this->remember($window);
        }

        return false;
    }

    /**
     * Windows that have ended and still have an unrecorded count.
     *
     * @return array<int, int> window => suppressed count
     */
    public function pending(): array
    {
        $pending = [];

        foreach ((array) Cache::get('audit:system_chain:windows', []) as $window) {
            if (is_int($window) && $window < $this->window()) {
                $pending[$window] = (int) Cache::get('audit:system_chain:suppressed:'.$window, 0);
            }
        }

        return $pending;
    }

    public function forget(int $window): void
    {
        Cache::forget('audit:system_chain:suppressed:'.$window);

        $windows = array_values(array_filter(
            (array) Cache::get('audit:system_chain:windows', []),
            fn ($known) => $known !== $window,
        ));
        Cache::put('audit:system_chain:windows', $windows, self::KEEP_SECONDS);
    }

    public function iso(int $window): string
    {
        return gmdate('Y-m-d\TH:i:s\Z', $window * self::WINDOW_SECONDS);
    }

    private function remember(int $window): void
    {
        $windows = (array) Cache::get('audit:system_chain:windows', []);
        $windows[] = $window;
        Cache::put('audit:system_chain:windows', array_values(array_unique($windows)), self::KEEP_SECONDS);
    }

    private function window(): int
    {
        return (int) floor(now()->getTimestamp() / self::WINDOW_SECONDS);
    }
}
