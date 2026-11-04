<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/*
| docs/database-design.md §3.2. After users, because updated_by references it.
*/
return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            CREATE TABLE organization_settings (
              organization_id uuid PRIMARY KEY REFERENCES organizations (id),
              monthly_token_limit integer NOT NULL CHECK (monthly_token_limit > 0),
              user_daily_request_limit integer NOT NULL CHECK (user_daily_request_limit > 0),
              max_input_chars integer NOT NULL DEFAULT 4000 CHECK (max_input_chars BETWEEN 1 AND 20000),
              updated_by uuid NULL REFERENCES users (id),
              updated_at timestamptz NOT NULL
            )
            SQL);

        $app = '"'.str_replace('"', '""', config()->string('database.connections.pgsql.username')).'"';
        DB::statement("GRANT SELECT, INSERT, UPDATE ON organization_settings TO {$app}");
    }

    public function down(): void
    {
        DB::statement('DROP TABLE organization_settings');
    }
};
