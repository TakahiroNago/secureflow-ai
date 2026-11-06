<?php

namespace Tests\Support;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;

/**
 * For scripts/test-worker-failure.sh only: a job that takes as long as it is told, to show what the worker's
 * time limit does to it. Its side effect is a line per run in a file of the container.
 */
final class QueueProbeJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable;

    public function __construct(
        public readonly string $id,
        public readonly int $seconds,
    ) {}

    public function handle(): void
    {
        $directory = sys_get_temp_dir().'/queue-probe';
        if (! is_dir($directory)) {
            mkdir($directory, 0700, true);
        }

        $file = $directory.'/'.basename($this->id).'.log';
        file_put_contents($file, gmdate('H:i:s').' start attempt='.$this->attempts()."\n", FILE_APPEND);
        sleep($this->seconds);
        file_put_contents($file, gmdate('H:i:s')." finish\n", FILE_APPEND);
    }
}
