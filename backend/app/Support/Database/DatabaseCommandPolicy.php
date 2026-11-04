<?php

namespace App\Support\Database;

use Illuminate\Console\Events\CommandStarting;
use Illuminate\Contracts\Console\Kernel as ConsoleKernel;
use Illuminate\Database\Console\DumpCommand;
use Illuminate\Database\Console\Migrations\FreshCommand;
use Illuminate\Database\Console\Migrations\RefreshCommand;
use Illuminate\Database\Console\Migrations\ResetCommand;
use Illuminate\Database\Console\Migrations\RollbackCommand;
use Illuminate\Database\Console\Seeds\SeedCommand;
use Illuminate\Database\Console\WipeCommand;
use Illuminate\Foundation\Console\KeyGenerateCommand;
use Illuminate\Queue\Console\ClearCommand as QueueClearCommand;
use Illuminate\Queue\Console\FlushFailedCommand;
use Illuminate\Support\Facades\Event;
use RuntimeException;

/**
 * Which console commands may run where (docs/database-design.md §4.5).
 *
 * DB::prohibitDestructiveCommands() is not used because it also blocks migrate:rollback, which
 * stays available on the development database through a managed procedure.
 */
final class DatabaseCommandPolicy
{
    private const SCHEMA_RESET_COMMANDS = ['migrate:fresh', 'migrate:refresh', 'migrate:reset', 'db:wipe'];

    public static function apply(string $environment): void
    {
        // Testing alone is not enough: the connection settings must also point at the test database.
        $resetAllowed = TestDatabaseGuard::configViolations() === [];

        FreshCommand::prohibit(! $resetAllowed);
        RefreshCommand::prohibit(! $resetAllowed);
        ResetCommand::prohibit(! $resetAllowed);
        WipeCommand::prohibit(! $resetAllowed);

        $productionEquivalent = self::isProductionEquivalent($environment);

        RollbackCommand::prohibit($productionEquivalent);
        KeyGenerateCommand::prohibit($productionEquivalent);
        QueueClearCommand::prohibit($productionEquivalent);
        FlushFailedCommand::prohibit($productionEquivalent);
        SeedCommand::prohibit($productionEquivalent);
        DumpCommand::prohibit($productionEquivalent);

        if ($resetAllowed) {
            // Laravel does not fire CommandStarting when APP_ENV is testing unless asked to, and
            // the server-side check runs from that event. A test covers this.
            app(ConsoleKernel::class)->rerouteSymfonyCommandEvents();
            Event::listen(CommandStarting::class, [self::class, 'guardSchemaReset']);
        }
    }

    /**
     * Anything not known to be safe, including an unknown or mistyped value, counts as production.
     */
    public static function isProductionEquivalent(string $environment): bool
    {
        return ! in_array($environment, ['local', 'testing'], true);
    }

    /**
     * The settings passed: also check what the server reports, and which connection is targeted.
     */
    public static function guardSchemaReset(CommandStarting $event): void
    {
        if (! in_array($event->command, self::SCHEMA_RESET_COMMANDS, true)) {
            return;
        }

        $connection = $event->input->getParameterOption('--database', null);
        if ($connection !== null && $connection !== TestDatabaseGuard::OWNER_CONNECTION) {
            throw new RuntimeException('Test database guard: schema resets must use the test owner connection');
        }

        TestDatabaseGuard::assertSafe();
    }
}
