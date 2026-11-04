<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/*
| docs/database-design.md §3.3. The id has no DEFAULT: Laravel generates UUIDv7 (§1).
*/
return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            CREATE TABLE users (
              id uuid PRIMARY KEY,
              organization_id uuid NOT NULL REFERENCES organizations (id),
              name varchar(100) NOT NULL,
              email citext NOT NULL UNIQUE,
              password varchar(255) NOT NULL,
              role varchar(16) NOT NULL CHECK (role IN ('admin', 'member', 'auditor')),
              is_active boolean NOT NULL DEFAULT true,
              failed_login_count smallint NOT NULL DEFAULT 0,
              locked_until timestamptz NULL,
              last_login_at timestamptz NULL,
              password_changed_at timestamptz NULL,
              created_at timestamptz NOT NULL,
              updated_at timestamptz NOT NULL
            )
            SQL);

        DB::statement('CREATE INDEX users_organization_id_index ON users (organization_id)');

        $app = '"'.str_replace('"', '""', config()->string('database.connections.pgsql.username')).'"';
        DB::statement("GRANT SELECT, INSERT, UPDATE ON users TO {$app}");
    }

    public function down(): void
    {
        DB::statement('DROP TABLE users');
    }
};
