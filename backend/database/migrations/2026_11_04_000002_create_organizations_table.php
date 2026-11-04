<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/*
| docs/database-design.md §3.1. The id has no DEFAULT: Laravel generates UUIDv7 (§1).
*/
return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            CREATE TABLE organizations (
              id uuid PRIMARY KEY,
              name varchar(100) NOT NULL,
              created_at timestamptz NOT NULL,
              updated_at timestamptz NOT NULL
            )
            SQL);

        $app = '"'.str_replace('"', '""', config()->string('database.connections.pgsql.username')).'"';
        DB::statement("GRANT SELECT, INSERT, UPDATE ON organizations TO {$app}");
    }

    public function down(): void
    {
        DB::statement('DROP TABLE organizations');
    }
};
