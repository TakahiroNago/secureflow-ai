<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use RuntimeException;

abstract class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Safety guard: tests must never touch the development database.
        $database = config('database.connections.pgsql.database');
        if ($database !== 'secureflow_test') {
            throw new RuntimeException('Tests must run against the secureflow_test database.');
        }
    }
}
