<?php

namespace App\Logging;

use Illuminate\Log\Logger;
use Monolog\Logger as Monolog;

/**
 * The "tap" of each channel in config/logging.php, so that a channel cannot be left out by accident.
 */
final class RedactLogs
{
    public function __invoke(Logger $logger): void
    {
        $monolog = $logger->getLogger();

        if ($monolog instanceof Monolog) {
            $monolog->pushProcessor(new RedactSensitiveData);
        }
    }
}
