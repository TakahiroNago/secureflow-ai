<?php

namespace Tests;

use App\Support\Database\TestDatabaseGuard;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Support\Facades\Artisan;
use RuntimeException;

abstract class TestCase extends BaseTestCase
{
    /**
     * Rolled back after tests that use DatabaseTransactions.
     *
     * @var list<string>
     */
    protected array $connectionsToTransact = [
        TestDatabaseGuard::APP_CONNECTION,
        TestDatabaseGuard::OWNER_CONNECTION,
    ];

    private static bool $schemaReady = false;

    /**
     * Runs before DatabaseTransactions opens its transactions.
     *
     * @return array<class-string, class-string>
     */
    protected function setUpTraits()
    {
        // Tests must never touch anything but the test database (docs/database-design.md §4.6).
        $violations = TestDatabaseGuard::configViolations();
        if ($violations !== []) {
            throw new RuntimeException('Test database guard: '.implode('; ', $violations));
        }

        if (! self::$schemaReady) {
            TestDatabaseGuard::assertSafe();

            // The owner builds the schema once per run; test queries use the application role.
            $status = Artisan::call('migrate:fresh', [
                '--database' => TestDatabaseGuard::OWNER_CONNECTION,
                '--force' => true,
            ]);
            if ($status !== 0) {
                throw new RuntimeException('Could not build the test schema: '.Artisan::output());
            }

            self::$schemaReady = true;
        }

        return parent::setUpTraits();
    }
}
